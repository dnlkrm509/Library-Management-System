const fs = require('fs');
const path = require('path');

const dotenv = require('dotenv');
dotenv.config();

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const PDFDocument = require('pdfkit');

const Resource = require('../models/resource');
const BorrowedHistory = require('../models/borrowedHistory');

const ITEMS_PER_PAGE = 2;

exports.getResources = (req, res, next) => {
    const page = +req.query.page || 1;

    Resource.fetchAll(page, ITEMS_PER_PAGE)
    .then(resourceData => {
        console.log(resourceData)
        res.render('shop/resources', {
            pageTitle: 'Resources',
            path: '/resources',
            resources: resourceData.resources,
            loggedInUser: req.user,
            previousPage: page - 1,
            currentPage: page,
            nextPage: page + 1,
            lastPage: Math.ceil(resourceData.itemsCount / ITEMS_PER_PAGE),
            hasPreviousPage: page > 1,
            hasNextPage: (page * ITEMS_PER_PAGE) < resourceData.itemsCount
        })
    })
    .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
    });
};

exports.getResource = (req, res, next) => {
    const resourceId = req.params.resourceId;
    Resource.findById(resourceId)
    .then(resource => {
        res.render('shop/detail', {
            pageTitle: resource.title,
            path: '/resources',
            resource,
            loggedInUser: req.user
        })
    })
    .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
    });
};

exports.getBorrow = (req, res, next) => {
    req.user.getBorrowed()
    .then(resources => {
        res.render('shop/borrow', {
            pageTitle: 'Your Borrowed Resources',
            path: '/borrow',
            resources
        })
    })
    .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
    });
};

exports.postBorrow = (req, res, next) => {
    const resourceId = req.body.resourceId;
    const returned = req.body.returned;

    Resource.findById(resourceId)
    .then(resource => {
        return req.user.borrow(resource);
    })
    .then(result => {
        if (returned === "true") {
            res.redirect('/borrow-history');
        } else if (returned === "false") {
            res.redirect('/borrow');
        }
    })
    .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
    });
};

exports.getCheckout = (req, res, next) => {
    const resourceId = req.query.resourceId;
    const returned = req.query.returned;

    let myResources;
    let total = 0;
    
    req.user.getBorrowed()
    .then(resources => {
        myResources = resources;
        resources.forEach(resource => {
            const returned = new Date();
            const due = new Date(resource.dueDate);

            const msPerDay = 1000 * 60 * 60 * 24;
            const lateDays = Math.ceil((returned - due) / msPerDay);

            total = lateDays > 0 ? (lateDays * 1.99) : 0;
        })

        return stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: resources.map(resource => {
                return {
                    price_data: {
                        currency: 'gbp',
                        product_data: {
                            name: resource.title,
                            description: resource.author + ", " + resource.publicationYear
                        },
                        unit_amount: total * 100
                    },
                    quantity: 1
                }
            }),
            mode: 'payment',
            success_url: req.protocol + '://' + req.get('host') + `/checkout/success?resourceId=${resourceId}&returned=${returned}`,
            cancel_url: req.protocol + '://' + req.get('host') + '/checkout/cancel'
        })
    })
    .then(session => {
        res.render('shop/checkout', {
            pageTitle: 'Checkout',
            path: '/checkout',
            resources: myResources,
            total,
            sessionId: session.id
        })
    })
    .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
    });
};

exports.getCheckoutSuccess = (req, res, next) => {
    const resourceId = req.query.resourceId;
    const returned = req.query.returned;

    console.log(resourceId, returned)

    Resource.findById(resourceId)
    .then(resource => {
        return req.user.borrow(resource);
    })
    .then(result => {
        if (returned === "true") {
            res.redirect('/borrow-history');
        } else if (returned === "false") {
            res.redirect('/borrow');
        }
    })
    .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
    });
};

exports.getBorrowedHistory = (req, res, next) => {
    req.user.getBorrowedHistory()
    .then(returneds => {
        res.render('shop/borrow-history', {
            pageTitle: 'Your Borrowed Resources History',
            path: '/borrow-history',
            returneds
        })
    })
    .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
    });
};

exports.getInvoice = (req, res, next) => {
    const borrowHistoryId = req.params.borrowHistoryId;
    BorrowedHistory.findByID(borrowHistoryId)
    .then(BH => {
        if (!BH) {
            return next(new Error('No resource found.'));
        }
        if (BH.user._id.toString() !== req.user._id.toString()) {
            return next(new Error('Unauthorized'));
        }

        const invoiceName = 'invoice-' + borrowHistoryId + '.pdf';
        const invoicePath = path.join('invoices', invoiceName);
    
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'inline; filename="' + invoiceName + '"');
        const pdfDoc = new PDFDocument({ margin: 50 });
        pdfDoc.pipe(fs.createWriteStream(invoicePath));
        pdfDoc.pipe(res);


        // 📄 Write multiple lines into the PDF
        pdfDoc.fontSize(20).text('Invoice', { underline: true });
        pdfDoc.moveDown();

        pdfDoc.fontSize(14).text(`Borrowed History ID: ${borrowHistoryId}`);
        pdfDoc.text(`Customer Email Address: ${BH.user.email || 'Unknown'}`);
        pdfDoc.moveDown();

        pdfDoc.text('Items:', { underline: true });
        pdfDoc.moveDown(0.5);

        // Loop through products and render each with image and details    
        // Product listing
        BH.resources.forEach(p => {
            const boxX = pdfDoc.x;
            const boxY = pdfDoc.y;
            const boxWidth = pdfDoc.page.width - pdfDoc.page.margins.left - pdfDoc.page.margins.right;
            const boxHeight = 130;

            // Simulate shadow with a slightly offset gray rectangle
            pdfDoc
                .save()
                .fillColor('#cccccc')
                .rect(boxX + 3, boxY + 3, boxWidth, boxHeight)
                .fill()
                .restore();

            // Draw main white box with border
            pdfDoc
                .save()
                .fillColor('#ffdfff')
                .strokeColor('#999999')
                .lineWidth(1)
                .rect(boxX, boxY, boxWidth, boxHeight)
                .fillAndStroke()
                .restore();

            // Text inside box
            const textX = boxX + 10;
            const textY = boxY + 10;

            pdfDoc.fillColor('black').fontSize(12).text(
                `Title: ${p.title}`,
                textX,
                textY,
                {
                width: boxWidth - 120,
                continued: false
                }
            );

            pdfDoc.fillColor('black').fontSize(12).text(
                `Author: ${p.author}`,
                textX,
                textY + 15,
                {
                width: boxWidth - 120,
                continued: false
                }
            );

            pdfDoc.fillColor('black').fontSize(12).text(
                `Punlication Year: ${p.publicationYear}`,
                textX,
                textY + 30,
                {
                width: boxWidth - 120,
                continued: false
                }
            );

            pdfDoc.fillColor('black').fontSize(12).text(
                `Genre: ${p.genre}`,
                textX,
                textY + 45,
                {
                width: boxWidth - 120,
                continued: false
                }
            );

            pdfDoc.fillColor('black').fontSize(12).text(
                `Due Date: ${p.dueDate}`,
                textX,
                textY + 60,
                {
                width: boxWidth - 120,
                continued: false
                }
            );

            pdfDoc.fillColor('black').fontSize(12).text(
                `Returned Date: ${p.returnedDate}`,
                textX,
                textY + 75,
                {
                width: boxWidth - 120,
                continued: false
                }
            );

            // Image inside box (to the right of the text)
            if (p.imageUrl) {
                try {
                pdfDoc.image(p.product.imageUrl, boxX + boxWidth - 170, boxY + 5, {
                    fit: [150, 150]
                });
                } catch (err) {
                pdfDoc.fontSize(10).fillColor('red').text('[Image missing]', boxX + boxWidth - 90, boxY + 30);
                }
            }

            
            pdfDoc.moveDown(2);
            pdfDoc.text('-------------');
            pdfDoc.text('Charge per day after due date: £1.99');
            
            const returned = new Date(p.returnedDate);
            const due = new Date(p.dueDate);

            const msPerDay = 1000 * 60 * 60 * 24;
            const lateDays = Math.ceil((returned - due) / msPerDay);

            const charge = lateDays > 0 ? (lateDays * 1.99) : 0;

            pdfDoc.text(`Total Price: £${charge.toFixed(2)}`, {
                bold: true
            });
            
            // Move below box
            pdfDoc.moveDown(6);
            pdfDoc.y = boxY + boxHeight + 10; // manually advance position
        });

        pdfDoc.end();

    })
    .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
    });
};