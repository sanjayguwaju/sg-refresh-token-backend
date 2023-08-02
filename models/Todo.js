const mongoose = require('mongoose');

const TodoSchema = mongoose.Schema({
  userId: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  completed: {
    type: Boolean,
    default: false,
  },
});

module.exports = mongoose.model('Todo', TodoSchema);
