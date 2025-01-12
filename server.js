const express = require('express');

const app = express();
const port = 3000;

// preserves query parameters
function redirectToOrigin(req, res, next) {
  req.url = '/';
  next();
}

console.log('Login Redirect URI --> /authorization-code/callback');
app.get('/authorization-code/callback', redirectToOrigin);
app.get('/magiclink/callback', redirectToOrigin);
app.get('/profile', redirectToOrigin);

app.use(express.static('./public'));

app.listen(port, () => {
  console.log(`App running at http://localhost:${port}`);
});
