exports.get404 = (req, res, nest) => {
    res.status(404).render('404', { pageTitle: 'Page Not Found', path: '/404' });
};

exports.get500 = (req, res, nest) => {
    res.status(500).render('500', { pageTitle: 'Error', path: '/500', errorMessage: error.message });
};