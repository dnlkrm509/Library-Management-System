const mongodb = require('mongodb');

const getDb = require('../util/database').getDb;

class BorrowedHistory {
    static findByID (borrowHistoryId) {
        const db = getDb();
        return db
        .collection('borrowed-history').findOne({_id: new mongodb.ObjectId(borrowHistoryId) })
    }
}

module.exports = BorrowedHistory;