const express = require('express');
const { body } = require('express-validator');

const router = express.Router();

const adminController = require('../controllers/admin');
const isAuth = require('../middleware/is-auth');

router.get('/add-resource', isAuth,adminController.getAddResource);

router.post('/add-resource', 
    [
        body('title')
        .isString()
        .isLength({min: 3})
        .trim(),
        body('author')
        .isString()
        .isLength({min: 3})
        .trim(),
        body('year')
        .isNumeric()
        .isLength({min: 4, max: 4})
        .trim(),
        body('genre')
        .isString()
        .isLength({min: 1})
        .trim()
    ],
    isAuth, 
    adminController.postAddResource
);

router.get('/resources', isAuth, adminController.getResources);

router.delete('/resource/:resourceId', isAuth, adminController.deleteResource);

router.get('/edit-resource/:resourceId', isAuth, adminController.getEditResource);

router.post('/edit-resource', 
    [
        body('title')
        .isString()
        .isLength({min: 3})
        .trim(),
        body('author')
        .isString()
        .isLength({min: 3})
        .trim(),
        body('year')
        .isNumeric()
        .isLength({min: 4, max: 4})
        .trim(),
        body('genre')
        .isString()
        .isLength({min: 1})
        .trim()
    ],
    isAuth, 
    adminController.postEditResource
);

module.exports = router;