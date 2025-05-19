const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
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
