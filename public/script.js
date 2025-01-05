let authClient = {};
var appState = {};

var config = {
  issuer: 'https://vivek-giri.oktapreview.com/oauth2/ausae177jfbCM7LBp1d7',
  clientId: '0oaehju4utBnhFRvP1d7',
  redirectUri: 'http://localhost:3000/authorization-code/callback',
  useInteractionCodeFlow: true,
  scopes: ['openid', 'email'],
};

authClient = new OktaAuth(config);

function signInUser() {
  // const username = document.getElementById('username').value.trim();
  const username = 'vivek.giri+newacc@okta.com';

  authClient.idx.authenticate({ username }).then(handleTransaction).catch(showError);
}

function handleTransaction(transaction) {
  console.log(transaction);

  switch (transaction.status) {
    case 'PENDING':
      if (transaction.nextStep.name === 'identify') {
        console.log('identify step');
        // renderDynamicSigninForm(transaction);
        break;
      }

      hideSigninForm();
      updateAppState({ transaction });
      showMFA();
      break;

    case 'SUCCESS':
      hideSigninForm();
      setTokens(transaction.tokens);
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

function showError(error) {
  console.log(error);
}

function logOutUser() {
  authClient.signOut();
}

function stringify(obj) {
  if (!obj) {
    return 'null';
  }
  return JSON.stringify(obj, null, 2);
}

function updateAppState(props) {
  Object.assign(appState, props);
}

function hideSigninForm() {
  document.getElementById('sign-in-form').style.display = 'none';
}
function showSigninForm() {
  document.getElementById('sign-in-form').style.display = 'block';
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
        console.log('more work needed in enroll profile');
        break;
      case 'enroll-poll':
        showMfaEnrollPollForm();
        break;
      default:
        throw new Error(`TODO: showMfa: handle nextStep: ${nextStep.name}`);
    }
  }
}

function showAuthenticatorVerificationData() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'email' || authenticator.type === 'phone') {
    document.getElementById('send-email-section').style.display = 'block';
    document.getElementById('mfa-submit').innerText = 'Send';
    return showAuthenticatorVerificationDataEmailAndPhone();
  }

  throw new Error(`TODO: handle authenticator-verification-data for authenticator type ${authenticator.type}`);
}
function showAuthenticatorVerificationDataEmailAndPhone() {
  const options = appState.transaction.nextStep.inputs[0].options[0].value;

  // TODO: Make a list from this options
  // console.log(options);
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

  throw new Error(`TODO: submitMfa: handle submit for nextStep: ${nextStep.name}`);
}

// this is used to send the email to the user
function submitAuthenticatorVerificationData() {
  const authenticator = appState.transaction.nextStep.authenticator;

  if (authenticator.type === 'email') {
    return submitAuthenticatorVerificationDataEmail();
  }
  throw new Error(`TODO: handle submit authenticator-verification-data for authenticator type ${authenticator.type}`);
}
function submitAuthenticatorVerificationDataEmail() {
  document.getElementById('send-email-section').style.display = 'none';
  const methodType = 'email';

  authClient.idx.authenticate({ methodType }).then(handleTransaction).catch(showError);
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

  // TODO: once the code is scanned, the Okta verify authenticator is set for the user
  // but nothing changes, in Okta Hosted widget....scanning the qr code takes you to the next page automatically
  // but in here, nothing changes...calling proceed after scanning returns the same response as earlier
  // effectively showing the same card

  authClient.idx.proceed({ verificationCode: passCode }).then(handleTransaction).catch(showError);
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
    return submitChallengeApp();
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
function submitChallengeApp() {
  document.getElementById('okta-verify-passcode-section').style.display = 'none';

  const passCode = document.querySelector('#okta-verify-passcode-section input[name=okta-verify-passcode]').value;

  authClient.idx.proceed({ verificationCode: passCode }).then(handleTransaction).catch(showError);
}

// ======================================================== ENROLL MFA FACTORS LIST ========================================================
function showMfaEnrollFactors() {
  const mfaList = appState.transaction.nextStep.inputs[0].options;
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

  authClient.idx.authenticate({ authenticator }).then(handleTransaction).catch(showError);
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
  document.getElementById('enroll-mfa-email-section').style.display = 'block';
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

function sendEmail(event) {
  document.getElementById('enroll-mfa-email-section').style.display = 'none';
  document.getElementById('enroll-mfa-email-code-section').style.display = 'block';

  const methodType = 'email';
  authClient.idx.proceed({ methodType }).then(handleTransaction).catch(showError);
  /* After sending this mail, the same type of response is returned
  with next step as enroll-authenticator and type email
  hence the same flow is repeated again and the send email card is still visible 
  so the diplay none for that card doesn't works*/
}

function submitEnrollChallengeEmail() {
  document.getElementById('enroll-mfa-email-code-section').style.display = 'none';
  document.getElementById('enroll-mfa-email-section').style.display = 'none';

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
  // const username = document.getElementById('forgot-pass-username').value.trim();
  const username = 'vivek.giri+testMFA@okta.com';

  document.getElementById('forgot-password-form').style.display = 'none';

  authClient.idx.recoverPassword({ username }).then(handleTransaction).catch(showError);
}

// ===================================================== REGISTER NEW USER =====================================================
function showRegistrationForm(e) {
  hideSigninForm();
  document.getElementById('register-new-user-form').style.display = 'block';
}

function showSignInFormSection(e) {
  showSigninForm();
  document.getElementById('register-new-user-form').style.display = 'none';
  document.getElementById('forgot-password-form').style.display = 'none';
}

function submitRegisterNewUser(e) {
  document.getElementById('register-new-user-form').style.display = 'none';

  // const email = document.getElementById('new-user-email').value.trim();
  // const firstName = document.getElementById('new-user-fname').value.trim();
  // const lastName = document.getElementById('new-user-lname').value.trim();

  const email = 'vivek.giri+newacc@okta.com';
  const firstName = 'VK';
  const lastName = 'NewAcc';

  authClient.idx.register({ firstName, lastName, email }).then(handleTransaction).catch(showError);
}
