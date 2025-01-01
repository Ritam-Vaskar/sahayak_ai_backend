const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'ritmvaskar0@gmail.com',
        pass: 'Ritam@2005',
    },
});

module.exports = transporter;
