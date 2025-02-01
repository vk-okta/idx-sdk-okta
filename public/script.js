let authClient = {};
var appState = {};
var config = {
  issuer: 'https://vivek-giri.oktapreview.com/oauth2/ausae177jfbCM7LBp1d7',
  clientId: '0oaehju4utBnhFRvP1d7',
  // issuer: 'https://hiconlabs.oktapreview.com/oauth2/aus9oi7lq0TVc1h581d7',
  // clientId: '0oaddhr715zGZVMv81d7',
  scopes: ['openid', 'profile', 'offline_access', 'okta.myAccount.password.manage', 'okta.myAccount.password.read'],
  redirectUri: 'http://localhost:3000/authorization-code/callback',
  useInteractionCodeFlow: true,
  transformAuthState,
};

async function transformAuthState(oktaAuth, authState) {
  if (!authState.isAuthenticated) {
    return authState;
  }

  // check if the user has an valid Okta SSO session
  // the user stores the getUserInfo data
  const user = await oktaAuth.token.getUserInfo();

  authState.isAuthenticated = !!user; // convert to boolean
  authState.users = user; // also store user object on authState

  return authState;
}

// Wait for DOM content to be loaded before starting the app
document.addEventListener('DOMContentLoaded', () => {
  // this loads the config from the sessionStorage
  loadConfig();

  // start the app
  main();
});

function main() {
  // if config object does not have issuer and client id
  if (!config.issuer && !config.clientId) {
    showConfigForm();
    return;
  }

  createAuthClient();

  // Subscribe to authState change event. Logic based on authState is done here.
  authClient.authStateManager.subscribe(async function (authState) {
    if (!authState.isAuthenticated) {
      // this I am setting here becuase putting idx.start in startApp() function
      // is starting the flow on page refresh causing errors

      // using this to check available idps and enabled features
      await authClient.idx.start().then(handleTransaction).catch(showError);

      renderUnAuthenticatedState();
    }

    // Render app based on the new authState
    renderApp();
  });

  handleIdpCallback();
  handleEmailCallback();

  startApp();
}

function startApp() {
  // Calculates initial auth state and fires change event for listeners
  // Also starts the token auto-renew service
  // this is needed if you want to refresh the page and stay on the
  // authenticated app
  authClient.start();
}

function createAuthClient() {
  try {
    authClient = new OktaAuth(config);

    sessionStorage.setItem('config', JSON.stringify(config));

    document.getElementById('config-section').innerText = stringify(config);
  } catch (error) {
    showError(error);
    console.log(error);
  }
}

function loadConfig() {
  const storedConfig = JSON.parse(sessionStorage.getItem('config'));

  if (storedConfig) Object.assign(config, storedConfig);
}

function renderApp() {
  const authState = authClient.authStateManager.getAuthState();
  document.getElementById('authState-section').innerText = stringify(authState);

  if (authState.isAuthenticated) {
    // if the user is already authenticated, directly display the tokens page
    return renderAuthenticatedState(authState);
  }

  return renderUnAuthenticatedState();
}

function renderAuthenticatedState(authState) {
  hideSigninForm();
  hideBackToHome();

  document.getElementById('auth-section').style.display = 'block';
  document.getElementById('accessToken').innerText = stringify(authState.accessToken);

  const userInfoData = authState.users || {};
  renderUserInfo(userInfoData);
}

function renderUnAuthenticatedState() {
  document.getElementById('auth-section').style.display = 'none';
  showSignInFormSection();
}

function showConfigForm() {
  document.getElementById('config-form-section').style.display = 'block';
  hideSigninForm();
}

function hideConfigForm() {
  document.getElementById('config-form-section').style.display = 'none';
}

function submitConfig() {
  const issuer = document.querySelector('#config-form-section input[name=issuer]').value.trim();
  const clientId = document.querySelector('#config-form-section input[name=clientId]').value.trim();
  const scopes = document.querySelector('#config-form-section input[name=scopes]').value.trim().split(' ');

  if (!issuer || !clientId || !scopes) return;

  hideConfigForm();
  showSignInFormSection();

  Object.assign(config, { issuer, clientId, scopes });
  createAuthClient();
}

async function submitSignInUser() {
  const username = document.getElementById('username').value.trim();
  const rememberMe = document.getElementById('rememberMe-checkbox').checked;

  updateAppState({ username });

  authClient.idx
    .authenticate(rememberMe ? { username, rememberMe } : { username })
    .then(handleTransaction)
    .catch(showError);
}

function handleTransaction(transaction) {
  console.log(transaction);

  if (transaction.messages) showTransactionMessage(transaction.messages);

  switch (transaction.status) {
    case 'PENDING':
      if (transaction.nextStep.name === 'identify') {
        console.log('identify step found');

        showSignInFormSection;
        // check for available features
        checkAvailableFeatures(transaction);

        break;
      }

      hideSigninForm();
      updateAppState({ transaction });
      showMFA();
      break;

    case 'SUCCESS':
      hideSigninForm();
      handleTokens(transaction);
      updateAppState({ transaction });
      break;

    case 'CANCELED':
      cancelTransaction();
      break;

    default:
      throw new Error('TODO: add handling for ' + transaction.status + ' status');
  }
}

function handleTokens(transaction) {
  if (transaction.tokens) {
    // when status is SUCCESS, transaction object has tokens in it
    setTokens(transaction.tokens);
  } else {
    // if the session exists, the status is SUCCESS but the transaction object
    // doesn't have tokens in it. Call proceed to get tokens
    authClient.idx.proceed().then(handleTransaction).catch(showError);
  }
}

function setTokens(tokens) {
  // There may also be a leftover "error" param from the auth flow.
  // Replace state with the "/" so the page can be reloaded cleanly.
  // not doing this, will have issues when IDP sets interaction error in URL
  window.history.replaceState({}, '', '/');

  if (!tokens) return;

  authClient.tokenManager.setTokens(tokens);

  authClient.tokenManager.getTokens().then(({ accessToken, idToken }) => {
    renderTokens(accessToken, idToken);
  });
}

function showTransactionMessage(messages) {
  const txt = messages[0].message;

  document.getElementById('transaction-msg').style.display = 'block';
  document.getElementById('transaction-msg-section').innerText = txt;
}

function showError(error) {
  document.getElementById('error').style.display = 'block';
  document.getElementById('error-section').innerText = error;
  console.log(error);
}

function logOutUser() {
  authClient.signOut();
}

function renewToken() {
  authClient.tokenManager.renew('accessToken').catch(showError);
}

function stringify(obj) {
  if (!obj) {
    return 'null';
  }
  return JSON.stringify(obj, null, 2);
}

function capitalizeFirstWord(str) {
  return str.trim().charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}

function updateAppState(props) {
  Object.assign(appState, props);
  document.getElementById('transaction-section').innerText = stringify(appState.transaction || {});
}

function hideSigninForm() {
  document.getElementById('sign-in-form').style.display = 'none';
}
function showSigninForm() {
  document.getElementById('sign-in-form').style.display = 'block';
}

function showSignInFormSection(e) {
  showSigninForm();
  document.getElementById('register-new-user-form').style.display = 'none';
  document.getElementById('forgot-password-form').style.display = 'none';
  document.getElementById('unlock-account-form').style.display = 'none';
  hideConfigForm();
}

async function renderTokens(accessToken, idToken) {
  document.getElementById('auth-section').style.display = 'block';
  document.getElementById('accessToken').innerText = stringify(accessToken);

  const userInfo = await authClient.token.getUserInfo(accessToken, idToken);
  renderUserInfo(userInfo);
}

function renderUserInfo(userInfo) {
  document.getElementById('userInfo').innerText = stringify(userInfo);
}

// ============================================ CANCEL TRANSACTION ==============================================
function hideBackToHome() {
  document.getElementById('back-to-home').style.display = 'none';
}

function backToHome() {
  if (!authClient) return;

  authClient.idx.cancel().then(handleTransaction).catch(showError);
}

function cancelTransaction() {
  window.history.replaceState({}, '', '/');
  window.location.reload();
}

function checkAvailableFeatures(transaction) {
  // show the list of all IDPS available
  const idpsList = transaction.availableSteps.filter((step) => step.name === 'redirect-idp');
  showAvailableIdps(idpsList);

  const rememberMe = transaction.nextStep.inputs.filter((step) => step.name === 'rememberMe');
  if (rememberMe.length) document.getElementById('rememberMe-section').style.display = 'block';

  // features: unlock account and Register User
  const features = transaction.enabledFeatures;
  features.forEach((elem) => {
    // only show unlock-account if available based on the app / org policy configuration.
    if (elem === 'unlock-account') {
      document.getElementById('unlock-account-user-section').style.display = 'block';
    } else if (elem === 'enroll-profile') {
      document.getElementById('register-user-section').style.display = 'block';
    }
  });
}

function showMFA() {
  const transaction = appState.transaction;

  if (transaction.status === 'PENDING') {
    const nextStep = transaction.nextStep;

    const messages = transaction?.messages;
    const key = messages && messages[0].i18n.key;

    // If Password Reset is not supported by ORG
    if (key === 'oie.selfservice.reset.password.not.allowed') {
      return;
    }

    switch (nextStep.name) {
      case 'authenticator-verification-data':
        showAuthenticatorVerificationData();
        break;
      case 'challenge-authenticator':
        showMfaChallenge();
        break;
      case 'select-authenticator-authenticate':
        showMfaRequired();
        break;
      case 'select-authenticator-enroll':
        showMfaEnrollFactors();
        break;
      case 'authenticator-enrollment-data':
        showAuthenticatorEnrollmentData();
        break;
      case 'enroll-authenticator':
        showMfaEnrollmentForm();
        break;
      case 'enroll-profile':
        showRegistrationForm();
        break;
      case 'enroll-poll':
        showMfaEnrollPollForm();
        break;
      case 'challenge-poll':
        showChallengePoll();
        break;
      case 'reset-authenticator':
        showResetAuthenticatorForm();
        break;
      case 'select-authenticator-unlock-account':
        showUnlockAccountFormWithRemediators();
        break;
      case 'redirect-idp':
        showAndRedirectToIDP();
        break;
      default:
        throw new Error(`TODO: showMfa handle nextStep: ${nextStep.name}`);
    }
  }
}

// ================================================== SOCIAL LOGIN ==================================================
function showAvailableIdps(idpsList) {
  const containerElement = document.getElementById('idp-button-section');
  containerElement.style.display = 'block';

  idpsList.forEach(function (elem) {
    const idpLabel = elem.idp.name;
    const idpLink = elem.href;

    const el = document.createElement('a');
    el.setAttribute('href', idpLink);
    el.setAttribute('class', 'idp-button');

    el.innerHTML = `Login with ${idpLabel}`;

    containerElement.appendChild(el);

    // Add a line break after the anchor tag
    const br = document.createElement('br');
    containerElement.appendChild(br);
  });
}

// Social/IDP callback
function handleIdpCallback() {
  // this returns a string
  const search = window.location.search;

  // Social/IDP callback
  if (authClient.idx.isInteractionRequired(search)) {
    return authClient.idx.proceed().then(handleTransaction).catch(showError);
  }

  // this returns an object on which we can use the has function
  const searchParams = new URLSearchParams(window.location.search);

  // check if the url has interaction_code, and then proceed
  if (searchParams.has('interaction_code')) {
    // handle interactionCode and save tokens
    return authClient.idx.proceed().then(handleTransaction).catch(showError);
  }
}

function showAndRedirectToIDP() {
  const nextStep = appState.transaction.nextStep;

  document.getElementById('redirect-section').style.display = 'block';
  document.getElementById('redirect-section').innerText = `Redirecting to ${capitalizeFirstWord(nextStep.type)} for Authentication`;

  window.location.replace(nextStep.href);
}

// ================================================== EMAIL CALLBACK ==================================================
function handleEmailCallback() {
  const search = window.location.search;

  if (authClient.idx.isEmailVerifyCallback(search)) {
    try {
      return authClient.idx.handleEmailVerifyCallback(search).then(handleTransaction).catch(showError);
    } catch (error) {
      if (authClient.idx.isEmailVerifyCallbackError(error)) {
        const { otp, state } = error;
        console.log('Error in handling email verify callback');
        console.log(otp, state);

        // can do stuff here like custom handling of callback error
      }
      console.log(error.message);
    }
  }
}

// ======================================================= SHOW MFA =======================================================

function backToMfaList(event) {
  document.getElementById('authenticator-verification-data-email-section').style.display = 'none';
  document.getElementById('authenticator-verification-data-app-section').style.display = 'none';
  document.getElementById('password-section').style.display = 'none';
  document.getElementById('webauthn-section').style.display = 'none';
  document.getElementById('security-question-section').style.display = 'none';

  const selectAuthenticatorStep = appState.transaction.availableSteps.filter((step) => step.name === 'select-authenticator-authenticate');

  // const reqMFA = selectAuthenticatorStep[0].inputs[0].options;

  // TODO: show back to mfa list only if there are multiple MFAs, if there is just one factor type
  // it won't make sense to have back to mfa list if there is one 1 factor type

  authClient.idx.proceed({ step: selectAuthenticatorStep[0].name }).then(handleTransaction).catch(showError);
}

function showAuthenticatorVerificationData() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'email' || authenticator.type === 'phone') {
    return showAuthenticatorVerificationDataEmailAndPhone();
  }

  if (authenticator.type === 'app') {
    return showAuthenticatorVerificationApp();
  }

  throw new Error(`TODO: handle authenticator-verification-data for authenticator type ${authenticator.type}`);
}

function showAuthenticatorVerificationDataEmailAndPhone() {
  document.getElementById('authenticator-verification-data-email-section').style.display = 'block';

  const options = appState.transaction.nextStep.inputs[0].options;

  const selectElem = document.querySelector('#authenticator-verification-data-email-section select[name=methodType]');

  options.forEach(function (option) {
    const el = document.createElement('option');
    el.setAttribute('value', option.value);
    el.innerText = option.label;
    selectElem.appendChild(el);
  });
}

function showAuthenticatorVerificationApp() {
  document.getElementById('authenticator-verification-data-app-section').style.display = 'block';

  const options = appState.transaction.nextStep.inputs[0].options;
  const selectElem = document.querySelector('#authenticator-verification-data-app-section select[name=methodType]');

  options.forEach(function (option) {
    const el = document.createElement('option');
    el.setAttribute('value', option.value);
    el.innerText = option.label;
    selectElem.appendChild(el);
  });
}

function showChallengePoll() {
  document.getElementById('challenge-poll-section').style.display = 'block';

  const pollOptions = appState.transaction.nextStep?.poll;

  if (pollOptions.required) {
    authClient.idx
      .poll({ refresh: 500 })
      .then((transaction) => {
        document.getElementById('challenge-poll-section').style.display = 'none';
        handleTransaction(transaction);
      })
      .catch(showError);
  }
}

// ============================================= SUBMIT MFA =============================================

function submitMfa() {
  const nextStep = appState.transaction.nextStep;

  if (nextStep.name === 'authenticator-verification-data') {
    return submitAuthenticatorVerificationData();
  }

  if (nextStep.name === 'authenticator-enrollment-data') {
    return submitAuthenticatorEnrollmentData();
  }

  // use the passcode sent in the email to further resume the transaction
  if (nextStep.name === 'challenge-authenticator') {
    return submitChallengeAuthenticator();
  }

  if (nextStep.name === 'enroll-authenticator') {
    return submitEnrollAuthenticator();
  }

  if (nextStep.name === 'enroll-poll') {
    return submitEnrollPoll();
  }

  if (nextStep.name === 'reset-authenticator') {
    return submitResetAuthenticator();
  }

  throw new Error(`TODO: submitMfa handle submit for nextStep: ${nextStep.name}`);
}

function submitAuthenticatorVerificationData() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'email' || authenticator.type === 'phone') {
    return submitAuthenticatorVerificationDataEmail();
  }

  if (authenticator.type === 'app') {
    return submitAuthenticatorVerificationDataApp();
  }

  throw new Error(`TODO: handle submit authenticator-verification-data for authenticator type ${authenticator.type}`);
}
function submitAuthenticatorVerificationDataEmail() {
  document.getElementById('authenticator-verification-data-email-section').style.display = 'none';

  const methodType = document.querySelector('#authenticator-verification-data-email-section select[name=methodType]').value;

  // changed from authenticate to proceed, so that this doesn't disrupt the recover password(RP) flow
  // when using authenticate, it tries to login to the app rather than continue to the RP flow
  authClient.idx.proceed({ methodType }).then(handleTransaction).catch(showError);
}

function submitAuthenticatorVerificationDataApp() {
  document.getElementById('authenticator-verification-data-app-section').style.display = 'none';

  const methodType = document.querySelector('#authenticator-verification-data-app-section select[name=methodType]').value;

  authClient.idx.authenticate({ methodType }).then(handleTransaction).catch(showError);
}

// display the field to input the MFA
function showMfaChallenge() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'email' || authenticator.type === 'phone') {
    // show the input to enter the passcode
    document.getElementById('email-code-section').style.display = 'block';
    return;
  }

  if (authenticator.type === 'password') {
    document.getElementById('password-section').style.display = 'block';
    return;
  }

  if (authenticator.type === 'security_question') {
    document.getElementById('security-question-section').style.display = 'block';

    // display the question in the page
    const questionText = appState.transaction.nextStep.authenticator.profile.question;
    document.querySelector('#security-question-section .sec-ques').innerText = questionText;

    return;
  }

  // Web AuthN
  if (authenticator.type === 'security_key') {
    document.getElementById('webauthn-section').style.display = 'block';
    handleWebAuthn();
    return;
  }

  // Okta-Verify Or Google-Authenticator
  if (authenticator.type === 'app') {
    const authenticatorName = authenticator.displayName;

    document.getElementById('app-authenticator-label').textContent = `Enter the code from the ${authenticatorName} app`;

    document.getElementById('okta-verify-passcode-section').style.display = 'block';
    return;
  }

  throw new Error(`TODO: handle challenge-authenticator for authenticator type ${authenticator.type}`);
}

function showMfaEnrollPollForm() {
  const authenticator = appState.transaction.nextStep.authenticator;
  // extract QR code data
  const qrCode = authenticator.contextualData.qrcode;

  const containerElem = document.getElementById('enroll-okta-verify-section');
  containerElem.style.display = 'block';

  const imgFrame = document.querySelector('#enroll-okta-verify-section .enroll-qrcode-image');
  imgFrame.innerHTML = '';

  const img = document.createElement('img');
  img.setAttribute('src', qrCode.href);
  imgFrame.appendChild(img);

  const pollOptions = appState.transaction.nextStep?.poll;
  if (pollOptions.required) {
    authClient.idx
      .poll({ refresh: 500 })
      .then((transaction) => {
        hideEnrollPoll();
        handleTransaction(transaction);
      })
      .catch(showError);
  }
}

function hideEnrollPoll() {
  // hide the enroll card
  const containerElem = document.getElementById('enroll-okta-verify-section');
  containerElem.style.display = 'none';

  // remove the image frame
  const imgFrame = document.querySelector('#enroll-okta-verify-section .enroll-qrcode-image');
  imgFrame.innerHTML = '';
}

async function handleWebAuthn() {
  const challengeData = appState.transaction.nextStep?.authenticator?.contextualData?.challengeData;

  const authEnrollments = appState.transaction.nextStep?.authenticatorEnrollments;
  // extract type of webauthn from the enrollments
  const authenticatorEnrollments = authEnrollments.filter((step) => step.type === 'security_key');

  // this builds the parameter so that credentials can be requested
  const options = OktaAuth.webauthn.buildCredentialRequestOptions(challengeData, authenticatorEnrollments);

  // this is a web authentication API, this looks up stored creds and
  // check the domain name to see if it matches the one used during enrollment
  // if this is a match, prompt for user consent
  // this returns binary formatted data
  const credential = await navigator.credentials.get(options);

  // this returns a string formatted object required to verify the user
  // res contains {id, clientData, authenticatorData, signatureData}
  const res = OktaAuth.webauthn.getAssertion(credential);

  const { clientData, authenticatorData, signatureData } = res;

  authClient.idx
    .proceed({ clientData, authenticatorData, signatureData })
    .then((transaction) => {
      handleTransaction(transaction);
      document.getElementById('webauthn-section').style.display = 'none';
    })
    .catch(showError);
}

// ================================================= SUBMIT CHALLENGE AUTHENTICATOR =================================================
function submitChallengeAuthenticator() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'email' || authenticator.type === 'phone') {
    return submitChallengeEmail();
  }

  if (authenticator.type === 'password') {
    return submitChallengePassword();
  }

  if (authenticator.type === 'security_question') {
    return submitChallengeQuestion();
  }

  if (authenticator.type === 'app') {
    // Okta verify can be of type push or code
    const oktaVerifyType = appState.transaction.nextStep.inputs[0].name;

    // if okta verify is of type code
    if (oktaVerifyType === 'verificationCode') return submitChallengeAppCode();

    throw new Error(`TODO: handle submit okta verify type for ${oktaVerifyType}`);
  }

  throw new Error(`TODO: handle submit challenge-authenticator for authenticator type ${authenticator.type}`);
}
function submitChallengeEmail() {
  document.getElementById('email-code-section').style.display = 'none';

  const passCode = document.querySelector('#email-code-section input[name=email-code]').value;

  authClient.idx.proceed({ verificationCode: passCode }).then(handleTransaction).catch(showError);
}
function submitChallengePassword() {
  document.getElementById('password-section').style.display = 'none';

  const password = document.querySelector('#password-section input[name=password]').value;

  authClient.idx.proceed({ password: password }).then(handleTransaction).catch(showError);
}
function submitChallengeQuestion() {
  document.getElementById('security-question-section').style.display = 'none';

  const answer = document.querySelector('#security-question-section input[name=sec-ques-ans]').value;

  const questionKey = appState.transaction.nextStep.authenticator.profile.questionKey;
  authClient.idx.proceed({ credentials: { questionKey, answer } }).then(handleTransaction).catch(showError);
}
function submitChallengeAppCode() {
  document.getElementById('okta-verify-passcode-section').style.display = 'none';

  const passCode = document.querySelector('#okta-verify-passcode-section input[name=okta-verify-passcode]').value;

  authClient.idx.proceed({ verificationCode: passCode }).then(handleTransaction).catch(showError);
}

function resendMfa() {
  const canResend = appState.transaction.nextStep?.canResend;

  if (!canResend) {
    return;
  }

  authClient.idx.proceed({ resend: true }).then(handleTransaction).catch(showError);
}

// ======================================================== ENROLL MFA FACTORS LIST ========================================================
function showMfaEnrollFactors() {
  // mfaList = [{label: 'Email', value: 'okta_email'}, {label: 'Password', value: 'okta_password'}]
  const mfaList = appState.transaction.nextStep.inputs[0].options;

  const canSkip = appState.transaction.nextStep.canSkip;
  if (canSkip) document.getElementById('enroll-skip-btn').style.display = 'block';

  const containerElement = document.getElementById('list-enroll-mfa-section');
  containerElement.style.display = 'block';

  mfaList.forEach(function (elem) {
    const mfaLabel = elem.label;
    const mfaVal = elem.value;

    const el = document.createElement('div');
    el.setAttribute('id', `enroll-factor-${mfaVal}`);
    el.setAttribute('class', `factor`);

    el.innerHTML = `
    <div class="factor">
      <span>${mfaLabel}</span>
      <button class="verify-button" onclick="selectMfaFactorForEnrollment(event, '${mfaVal}')">Enroll</button>
    </div>
  `;

    containerElement.appendChild(el);
  });
}

function hideMfaEnroll() {
  const containerElement = document.getElementById('list-enroll-mfa-section');
  containerElement.style.display = 'none';

  // Clear only the dynamically inserted MFA factors (div elements retain the label)
  const mfaElements = containerElement.querySelectorAll('.factor');
  mfaElements.forEach((el) => el.remove());
}

function selectMfaFactorForEnrollment(e, authenticator) {
  hideMfaEnroll();

  authClient.idx.proceed({ authenticator }).then(handleTransaction).catch(showError);
}

function submitSkipEnroll(e) {
  hideMfaEnroll();

  authClient.idx.proceed({ skip: true }).then(handleTransaction).catch(showError);
}

// ======================================================== ENROLL IN MFA ========================================================

function showMfaEnrollmentForm() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'security_question') {
    // authenticator stores different questions that needs to be rendered
    return showEnrollSecurityQuestion(authenticator);
  }

  if (authenticator.type === 'email' || authenticator.type === 'phone') {
    return showEnrollEmail();
  }

  if (authenticator.type === 'password') {
    return showEnrollPassword();
  }

  // web authn
  if (authenticator.type === 'security_key') {
    return showEnrollWebAuthn();
  }

  if (authenticator.type === 'app') {
    return showEnrollApp();
  }

  throw new Error(`TODO: handle enroll showMfaEnrollmentForm for authenticator type ${authenticator.type}`);
}

function showEnrollSecurityQuestion(authenticator) {
  document.getElementById('enroll-mfa-question-section').style.display = 'block';

  const securityQuestions = authenticator.contextualData.questions;

  const selectElem = document.querySelector('#enroll-mfa-question-section select[name=enroll-questions]');

  securityQuestions.forEach(function (question) {
    const el = document.createElement('option');
    el.setAttribute('value', question.questionKey);
    el.innerText = question.question;
    selectElem.appendChild(el);
  });
}

function showEnrollEmail() {
  document.getElementById('enroll-mfa-email-code-section').style.display = 'block';
}

function showEnrollApp() {
  const authenticator = appState.transaction.nextStep.authenticator;
  // extract QR code data
  const qrCode = authenticator.contextualData.qrcode;
  const sharedSecret = authenticator.contextualData.sharedSecret;

  const containerElem = document.getElementById('enroll-app-section');
  containerElem.style.display = 'block';

  const keyLabel = document.querySelector('#enroll-app-section .enroll-google-app-key');
  keyLabel.textContent = sharedSecret;

  const imgFrame = document.querySelector('#enroll-app-section .enroll-qrcode-image');
  imgFrame.innerHTML = '';

  const img = document.createElement('img');
  img.setAttribute('src', qrCode.href);
  imgFrame.appendChild(img);
}

function hideEnrollApp() {
  // hide the enroll card
  const containerElem = document.getElementById('enroll-app-section');
  containerElem.style.display = 'none';

  // remove the image frame
  const imgFrame = document.querySelector('#enroll-app-section .enroll-qrcode-image');
  imgFrame.innerHTML = '';

  // remove key
  const keyLabel = document.querySelector('#enroll-app-section .enroll-google-app-key');
  keyLabel.textContent = '';
}

function showEnrollPassword() {
  document.getElementById('enroll-mfa-password-section').style.display = 'block';

  // the password rules is stored in authenticator
  const authenticator = appState.transaction.nextStep.authenticator;
  showPasswordRules(authenticator.settings);
}

function submitEnrollAuthenticator() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'security_question') {
    return submitEnrollChallengeQuestion();
  }

  if (authenticator.type === 'email' || authenticator.type === 'phone') {
    return submitEnrollChallengeEmail();
  }

  if (authenticator.type === 'password') {
    return submitEnrollChallengePassword();
  }

  if (authenticator.type === 'app') {
    return submitEnrollChallengeApp();
  }

  throw new Error(`TODO: handle submit enrollment submitEnrollAuthenticator for authenticator type ${authenticator.type}`);
}

function submitEnrollChallengeQuestion() {
  document.getElementById('enroll-mfa-question-section').style.display = 'none';

  const answer = document.querySelector('#enroll-mfa-question-section input[name=enroll-answer]').value;
  const questionKey = document.querySelector('#enroll-mfa-question-section select[name=enroll-questions]').value;

  authClient.idx.proceed({ credentials: { questionKey, answer } }).then(handleTransaction).catch(showError);
}

function submitEnrollChallengeEmail() {
  document.getElementById('enroll-mfa-email-code-section').style.display = 'none';

  const passCode = document.querySelector('#enroll-mfa-email-code-section input[name=enroll-email-code]').value;

  authClient.idx.proceed({ verificationCode: passCode }).then(handleTransaction).catch(showError);
}

function submitEnrollChallengePassword() {
  const newPass = document.querySelector('#enroll-mfa-password-section input[name=enroll-password]').value;
  const cnfNewPass = document.querySelector('#enroll-mfa-password-section input[name=enroll-password-cnf]').value;

  if (newPass !== cnfNewPass) {
    document.querySelector('#enroll-mfa-password-section .password-validation-error').style.display = 'block';
    return;
  }

  document.getElementById('enroll-mfa-password-section').style.display = 'none';

  authClient.idx.proceed({ password: newPass }).then(handleTransaction).catch(showError);
}

function submitEnrollChallengeApp() {
  document.getElementById('enroll-app-section').style.display = 'none';
  hideEnrollApp();

  const passCode = document.querySelector('#enroll-app-section input[name=enroll-app-code]').value;

  authClient.idx.proceed({ verificationCode: passCode }).then(handleTransaction).catch(showError);
}

function showAuthenticatorEnrollmentData() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'phone') {
    return showAuthenticatorEnrollmentPhone();
  }

  throw new Error(`TODO: handle authenticator-enrollment-data for authenticator type ${authenticator.type}`);
}

function showAuthenticatorEnrollmentPhone() {
  document.getElementById('authenticator-enroll-mfa-section').style.display = 'block';

  const options = appState.transaction.nextStep.inputs[0].options;

  const selectElem = document.querySelector('#authenticator-enroll-mfa-section select[name=methodType]');

  options.forEach(function (option) {
    const el = document.createElement('option');
    el.setAttribute('value', option.value);
    el.innerText = option.label;
    selectElem.appendChild(el);
  });
}

function hideAuthEnrollList() {
  // Get the select element
  const selectElem = document.querySelector('#authenticator-enroll-mfa-section select[name=methodType]');

  // Clear any existing options, this will remove all options
  selectElem.innerHTML = '';
}

function submitAuthenticatorEnrollmentData() {
  const methodType = document.querySelector('#authenticator-enroll-mfa-section select[name=methodType]').value;
  const phoneNumber = document.querySelector('#authenticator-enroll-mfa-section input[name=enrollment-phone-number]').value.trim();

  document.getElementById('authenticator-enroll-mfa-section').style.display = 'none';
  hideAuthEnrollList();

  authClient.idx.proceed({ methodType, phoneNumber }).then(handleTransaction).catch(showError);
}

async function showEnrollWebAuthn() {
  document.getElementById('enroll-webauthn-section').style.display = 'block';

  const activationData = appState.transaction.nextStep?.authenticator?.contextualData?.activationData;

  const authenticatorEnrollments = appState.transaction.nextStep?.authenticatorEnrollments;

  // this builds the parameter needed to create new credential
  const options = OktaAuth.webauthn.buildCredentialCreationOptions(activationData, authenticatorEnrollments);

  // browser prompts the user to choose an authenticator
  const credential = await navigator.credentials.create(options);

  // after the user chooses the authenticator, ask for consent to create creds.
  // The private and public key pairs are created.
  // The private key is stored internally on the device and linked to the user and domain name.

  // convert to string before sending it to Okta servers
  const res = OktaAuth.webauthn.getAttestation(credential);

  const { clientData, attestation } = res;

  authClient.idx
    .proceed({ clientData, attestation })
    .then((transaction) => {
      handleTransaction(transaction);
      document.getElementById('enroll-webauthn-section').style.display = 'none';
    })
    .catch(showError);
}

// ======================================================== MFA REQUIRED ========================================================
function showMfaRequired() {
  const mfaList = appState.transaction.nextStep.inputs[0].options;
  // mfaList = [{label: 'Email', value: 'okta_email'}, {label: 'Password', value: 'okta_password'}]

  const containerElement = document.getElementById('list-required-mfa-section');
  containerElement.style.display = 'block';

  mfaList.forEach(function (elem) {
    const mfaLabel = elem.label;
    const mfaVal = elem.value;

    const el = document.createElement('div');
    el.setAttribute('id', `verify-factor-${mfaVal}`);
    el.setAttribute('class', `factor`);

    el.innerHTML = `
    <div class="factor">
      <span>${mfaLabel}</span>
      <button class="verify-button" onclick="selectMfaFactorForVerification(event, '${mfaVal}')">Verify</button>
    </div>
  `;

    containerElement.appendChild(el);
  });
}

function hideMfaReqList() {
  // the dynamically inserted list of MFA needs to be cleared
  const containerElement = document.getElementById('list-required-mfa-section');
  containerElement.style.display = 'none';

  // Clear only the dynamically inserted MFA factors (div elements retain the label)
  const mfaElements = containerElement.querySelectorAll('.factor');
  mfaElements.forEach((el) => el.remove());
}

function selectMfaFactorForVerification(e, authenticator) {
  hideMfaReqList();

  authClient.idx.proceed({ authenticator }).then(handleTransaction).catch(showError);
}

// ===================================================== RECOVER PASSWORD FLOW =====================================================
function showForgotPassword(e) {
  hideSigninForm();
  document.getElementById('forgot-password-form').style.display = 'block';
}

function submitForgotPassword(e) {
  const username = document.getElementById('forgot-pass-username').value.trim();

  updateAppState({ username });

  document.getElementById('forgot-password-form').style.display = 'none';

  authClient.idx.recoverPassword({ username }).then(handleTransaction).catch(showError);
}

function showResetAuthenticatorForm() {
  document.getElementById('reset-authenticator-section').style.display = 'block';

  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'password') {
    return showNewPasswordForm();
  }

  throw new Error(`TODO: handle reset-authenticator for authenticator: ${authenticator.type}`);
}

function showNewPasswordForm() {
  document.querySelector('#reset-authenticator-section .heading').innerText = 'Reset your Password';

  // the password rules is stored in authenticator
  const authenticator = appState.transaction.nextStep.authenticator;
  showPasswordRules(authenticator.settings);
}

function submitResetAuthenticator() {
  const newPass = document.querySelector('#reset-authenticator-section input[name=new-password]').value;
  const cnfNewPass = document.querySelector('#reset-authenticator-section input[name=new-password-cnf]').value;

  if (newPass !== cnfNewPass) {
    showPasswordValidationError("Both the password doesn't match");
    return;
  }

  document.getElementById('reset-authenticator-section').style.display = 'none';
  hidePasswordRules();

  authClient.idx.proceed({ password: newPass }).then(handleTransaction).catch(showError);
}

function showPasswordRules(rules) {
  const complexityRules = rules?.complexity;

  const rulesLabel = [];

  Object.keys(complexityRules).forEach((rule) => {
    if (rule === 'excludeUsername' && complexityRules[rule]) rulesLabel.push('Username can not be part of password');
    if (rule === 'minLength' && complexityRules[rule] > 0)
      rulesLabel.push(`Minimum Length of Password should be ${complexityRules['minLength']}`);
    if (rule === 'minLowerCase' && complexityRules[rule] > 0)
      rulesLabel.push(`Password should have atleast ${complexityRules['minLowerCase']} lower case characters`);
    if (rule === 'minUpperCase' && complexityRules[rule] > 0)
      rulesLabel.push(`Password should have atleast ${complexityRules['minUpperCase']} upper case characters`);
    if (rule === 'minNumber' && complexityRules[rule] > 0)
      rulesLabel.push(`Password should have atleast ${complexityRules['minNumber']} numeric characters`);
    if (rule === 'minSymbol' && complexityRules[rule] > 0)
      rulesLabel.push(`Password should have atleast ${complexityRules['minSymbol']} special characters`);
  });

  if (!rulesLabel.length) return;

  const container = document.querySelector('#password-rules-group');
  container.style.display = 'block';

  rulesLabel.forEach(function (elem) {
    const el = document.createElement('div');

    el.innerHTML = `<span id='rules-label'>${elem}</span>`;

    container.appendChild(el);
  });
}

function hidePasswordRules() {
  const container = document.querySelector('#password-rules-group');
  container.style.display = 'none';

  container.innerHTML = '';
}

function showPasswordValidationError(errorText) {
  document.querySelector('#reset-authenticator-section .password-validation-error').style.display = 'block';
  document.querySelector('#reset-authenticator-section .password-validation-error').innerText = errorText;
}

// ===================================================== REGISTER NEW USER =====================================================
function showRegistrationForm(e) {
  hideSigninForm();
  document.getElementById('register-new-user-form').style.display = 'block';
}

function submitRegisterNewUser(e) {
  document.getElementById('register-new-user-form').style.display = 'none';

  const email = document.getElementById('new-user-email').value.trim();
  const firstName = document.getElementById('new-user-fname').value.trim();
  const lastName = document.getElementById('new-user-lname').value.trim();

  updateAppState({ username: email });

  authClient.idx.register({ firstName, lastName, email }).then(handleTransaction).catch(showError);
}

// ===================================================== UNLOCK ACCOUNT =====================================================
function showUnlockAccountForm(e) {
  hideSigninForm();
  document.getElementById('unlock-account-form').style.display = 'block';
}

function submitUnlockAccount(e) {
  document.getElementById('unlock-account-form').style.display = 'none';

  const username = document.getElementById('unlock-account-username').value.trim();

  updateAppState({ username });

  authClient.idx.unlockAccount({ username }).then(handleTransaction).catch(showError);
}

function showUnlockAccountFormWithRemediators() {
  document.getElementById('unlock-account-with-rmd-form').style.display = 'block';

  // dynamically inserting the username because as of now in Okta username is needed
  document.getElementById('unlock-account-username-with-rmd').value = appState.username;
  document.getElementById('unlock-account-username-with-rmd').disabled = true;

  const mfaList = appState.transaction.nextStep.inputs[1].options;

  const containerElement = document.getElementById('unlock-account-rmd-list');
  containerElement.style.display = 'block';

  mfaList.forEach(function (elem) {
    const mfaLabel = elem.label;
    const mfaVal = elem.value;

    const el = document.createElement('div');
    el.setAttribute('id', `verify-factor-${mfaVal}`);
    el.setAttribute('class', `factor`);

    el.innerHTML = `
    <div class="factor">
      <span>${mfaLabel}</span>
      <button class="verify-button" onclick="selectMfaFactorForUnlockAccount(event, '${mfaVal}')">Verify</button>
    </div>
  `;

    containerElement.appendChild(el);
  });
}

function hideMfaUnlockList() {
  // the dynamically inserted list of MFA needs to be cleared
  const containerElement = document.getElementById('unlock-account-rmd-list');
  containerElement.style.display = 'none';

  // Clear only the dynamically inserted MFA factors (div elements retain the label)
  const mfaElements = containerElement.querySelectorAll('.factor');
  mfaElements.forEach((el) => el.remove());
}

function selectMfaFactorForUnlockAccount(e, authenticator) {
  document.getElementById('unlock-account-with-rmd-form').style.display = 'none';

  hideMfaUnlockList();

  authClient.idx.proceed({ username: appState.username, authenticator }).then(handleTransaction).catch(showError);
}

// ============================================= CHANGE PASSWORD =============================================
function submitNewPass(event) {
  const newPassword = document.querySelector('#change-password-section input[name=change-password]').value;

  authClient.myaccount
    .updatePassword({ payload: { profile: { password: newPassword } } })
    .then(() => {
      console.log('Password changed successfully!!');
    })
    .catch(showError);
}

