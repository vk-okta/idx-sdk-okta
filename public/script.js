let authClient = {};
var appState = {};
var config = {};

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
  // this loads the config from the localstorage
  loadConfig();

  // start the app
  main();
});

function main() {
  // if config object is empty show config form
  if (Object.keys(config).length === 0) {
    showConfigForm();
    return;
  }

  createAuthClient();

  // Subscribe to authState change event. Logic based on authState is done here.
  authClient.authStateManager.subscribe(function (authState) {
    if (!authState.isAuthenticated) {
      renderUnAuthenticatedState();
    }

    // Render app based on the new authState
    renderApp();
  });

  // Calculates initial auth state and fires change event for listeners
  // Also starts the token auto-renew service
  // this is needed if you want to refresh the page and stay on the
  // authenticated app
  authClient.start();
}

function createAuthClient() {
  try {
    authClient = new OktaAuth({
      ...config,
      redirectUri: 'http://localhost:3000/authorization-code/callback',
      useInteractionCodeFlow: true,
      transformAuthState,
    });

    const showConfigData = {
      ...config,
      redirectUri: 'http://localhost:3000/authorization-code/callback',
      useInteractionCodeFlow: true,
    };

    localStorage.setItem('config', JSON.stringify(showConfigData));

    document.getElementById('config-section').innerText = stringify(showConfigData);
  } catch (error) {
    showError(error);
    console.log(error);
  }
}

function loadConfig() {
  const storedConfig = JSON.parse(localStorage.getItem('config'));

  if (storedConfig) Object.assign(config, storedConfig);
}

function renderApp() {
  const authState = authClient.authStateManager.getAuthState();

  if (authState.isAuthenticated) {
    // if the user is already authenticated, directly display the tokens page
    return renderAuthenticatedState(authState);
  }

  return renderUnAuthenticatedState();
}

function renderAuthenticatedState(authState) {
  hideSigninForm();
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
  createAuthClient()
}

function submitSignInUser() {
  const username = document.getElementById('username').value.trim();

  updateAppState({ username });

  authClient.idx.authenticate({ username }).then(handleTransaction).catch(showError);
}

function renderDynamicSigninForm(transaction) {
  document.getElementById('dynamic-signin-form-section').style.display = 'block';
  hideSigninForm();

  const inputs = transaction.nextStep.inputs;

  // set the display to block of all the sections present in the inputs array
  if (inputs.some((input) => input.name === 'username')) {
    document.querySelector('#dynamic-signin-form-section .dynamic-username-group').style.display = 'block';
  }

  // submitDynamicFormAuto();
}

function submitDynamicFormAuto() {
  // FIXME: BIG RED FLAG, Ideally imo the identify-step should not be there
  // TRY TO AVOID THE FLOW COMING HERE LIKE A PLAGUE
  // here I am using the username stored in the appstate
  const storedUsername = appState.username;

  if (!storedUsername) return;

  console.log('Using username stored in the appstate to skip the identify-step');

  // submit the form with the stored username
  submitDynamicSigninForm({}, storedUsername);
}

function submitDynamicSigninForm(event, storedUser) {
  document.getElementById('dynamic-signin-form-section').style.display = 'none';

  const username = storedUser
    ? storedUser
    : document.querySelector('#dynamic-signin-form-section input[name=dynamic-username]').value.trim();

  return authClient.idx.proceed({ username }).then(handleTransaction).catch(showError);
}

function handleTransaction(transaction) {
  console.log(transaction);

  if (transaction.messages) showTransactionMessage(transaction.messages);

  switch (transaction.status) {
    case 'PENDING':
      if (transaction.nextStep.name === 'identify') {
        renderDynamicSigninForm(transaction);
        break;
      }

      hideSigninForm();
      updateAppState({ transaction });
      showMFA();
      break;

    case 'SUCCESS':
      hideSigninForm();
      setTokens(transaction.tokens);
      updateAppState({ transaction });
      break;
    default:
      throw new Error('TODO: add handling for ' + transaction.status + ' status');
  }
}

function setTokens(tokens) {
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

function updateAppState(props) {
  Object.assign(appState, props);
  document.getElementById('transaction-section').innerText = stringify(appState.transaction?.nextStep || appState.transaction || {});
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

function showMFA() {
  const transaction = appState.transaction;

  if (transaction.status === 'PENDING') {
    const nextStep = transaction.nextStep;
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
      default:
        throw new Error(`TODO: showMfa handle nextStep: ${nextStep.name}`);
    }
  }
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
}

function submitMfa() {
  const nextStep = appState.transaction.nextStep;

  if (nextStep.name === 'authenticator-verification-data') {
    return submitAuthenticatorVerificationData();
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

  if (nextStep.name === 'challenge-poll') {
    return submitChallengePoll();
  }

  if (nextStep.name === 'reset-poll') {
    return submitChallengePoll();
  }

  if (nextStep.name === 'reset-authenticator') {
    return submitResetAuthenticator();
  }

  throw new Error(`TODO: submitMfa handle submit for nextStep: ${nextStep.name}`);
}

function submitAuthenticatorVerificationData() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'email') {
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

function submitChallengePoll() {
  document.getElementById('challenge-poll-section').style.display = 'none';

  const pollOptions = appState.transaction.nextStep?.poll;

  if (pollOptions.required) {
    authClient.idx.poll(pollOptions.refresh).then(handleTransaction).catch(showError);
  }
}

// display the field to input the MFA
function showMfaChallenge() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'email') {
    // show the input to enter the passcode
    document.getElementById('email-code-section').style.display = 'block';
  }

  if (authenticator.type === 'phone') {
    document.getElementById('phone-code-section').style.display = 'block';
  }

  if (authenticator.type === 'password') {
    document.getElementById('password-section').style.display = 'block';
  }

  if (authenticator.type === 'security_question') {
    document.getElementById('security-question-section').style.display = 'block';

    // display the question in the page
    const questionText = appState.transaction.nextStep.authenticator.profile.question;
    document.querySelector('#security-question-section .sec-ques').innerText = questionText;
  }

  // OKTA-VERIFY
  if (authenticator.type === 'app') {
    document.getElementById('okta-verify-passcode-section').style.display = 'block';
  }
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
}

function hideEnrollPoll() {
  // hide the enroll card
  const containerElem = document.getElementById('enroll-okta-verify-section');
  containerElem.style.display = 'none';

  // remove the image frame
  const imgFrame = document.querySelector('#enroll-okta-verify-section .enroll-qrcode-image');
  imgFrame.innerHTML = '';
}

function submitEnrollPoll() {
  hideEnrollPoll();

  const pollOptions = appState.transaction.nextStep?.poll;
  if (pollOptions.required) {
    authClient.idx.poll(pollOptions.refresh).then(handleTransaction).catch(showError);
  }
}

// ================================================= SUBMIT CHALLENGE AUTHENTICATOR =================================================
function submitChallengeAuthenticator() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'email') {
    return submitChallengeEmail();
  }

  if (authenticator.type === 'phone') {
    return submitChallengePhone();
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
function submitChallengePhone() {
  document.getElementById('sms-code-section').style.display = 'none';

  const passCode = document.querySelector('#sms-code-section input[name=sms-code]').value;

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

// ======================================================== ENROLL MFA FACTORS LIST ========================================================
function showMfaEnrollFactors() {
  const mfaList = appState.transaction.nextStep.inputs[0].options;
  const canSkip = appState.transaction.nextStep.canSkip;
  // mfaList = [{label: 'Email', value: 'okta_email'}, {label: 'Password', value: 'okta_password'}]

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
      ${canSkip ? `<button class="skip-verify-button" onclick="skipMfaFactorForEnrollment(event)">Skip</button>` : ``} 
      <button class="verify-button" onclick="selectMfaFactorForEnrollment(event, '${mfaVal}')">Verify</button>
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

function skipMfaFactorForEnrollment(e) {
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

  if (authenticator.type === 'email') {
    return showEnrollEmail();
  }

  if (authenticator.type === 'password') {
    return showEnrollPassword();
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

function showEnrollPassword() {
  document.getElementById('enroll-mfa-password-section').style.display = 'block';
}

function submitEnrollAuthenticator() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'security_question') {
    return submitEnrollChallengeQuestion();
  }

  if (authenticator.type === 'email') {
    return submitEnrollChallengeEmail();
  }

  if (authenticator.type === 'password') {
    return submitEnrollChallengePassword();
  }

  throw new Error(`TODO: handle submit enrollment submitEnrollAuthenticator for authenticator type ${authenticator.type}`);
}

function submitEnrollChallengeQuestion() {
  document.getElementById('enroll-mfa-question-section').style.display = 'none';

  const answer = document.querySelector('#enroll-mfa-question-section input[name=enroll-answer]').value;
  const questionKey = document.querySelector('#enroll-mfa-question-section select[name=enroll-questions]').value;

  authClient.idx.authenticate({ credentials: { questionKey, answer } }).then(handleTransaction).catch(showError);
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

  // const username = document.getElementById('unlock-account-username').value.trim();
  const username = 'vivek.giri+newacc@okta.com';

  updateAppState({ username });

  // this will need reviewing based on the JIRA https://oktainc.atlassian.net/browse/OKTA-848066
  authClient.idx.unlockAccount({ username }).then(handleTransaction).catch(showError);
}

function showUnlockAccountFormWithRemediators() {
  document.getElementById('unlock-account-with-rmd-form').style.display = 'block';

  // dynamically inserting the username because as of now in Okta username is needed
  // in Okta SIW as of now the username is needed
  document.getElementById('unlock-account-username-with-rmd').value = appState.username;

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

  // the username needs to be passed as of now
  authClient.idx.proceed({ username: appState.username, authenticator }).then(handleTransaction).catch(showError);
}

// TODO: Add support for password recovery and unlock account with okta verify. currently only email support
