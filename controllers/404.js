exports.get404 = (req, res, nest) => {
    res.status(404).render('404', { pageTitle: 'Page Not Found', path: '/404' });
}