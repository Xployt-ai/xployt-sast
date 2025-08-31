const express = require('express');
const User = require('./models/User');

const app = express();

app.get('/users/:id', (req, res) => {
  const { id } = req.params;
  User.find({ $where: id });
});

app.post('/search', (req, res) => {
  const { operator, value } = req.body;
  User.findOne({ [operator]: value });
});

app.get('/filter', (req, res) => {
  const query = req.query.filter;
  User.find(query);
});

app.listen(3000);
