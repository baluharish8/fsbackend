const mongoose = require('mongoose');

const SearchQuerySchema = new mongoose.Schema({
    query: String,
    timestamp: { type: Date, default: Date.now }
});

const ClickSchema = new mongoose.Schema({
    itemId: String,
    timestamp: { type: Date, default: Date.now }
});

const ViewSchema = new mongoose.Schema({
    itemId: String,
    timestamp: { type: Date, default: Date.now },
    categories: String // Storing a single category as a string
});

const SessionSchema = new mongoose.Schema({
    duration: {
        type: Number,
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});
const Session = mongoose.model('Session', SessionSchema, 'Session');
const SearchQuery = mongoose.model('SearchQuery', SearchQuerySchema,'SearchQuery');
const Click = mongoose.model('Click', ClickSchema,'Click');
const View = mongoose.model('View', ViewSchema,'View');

module.exports = { SearchQuery, Click, View,Session };
