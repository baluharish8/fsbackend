const jwt = require('jsonwebtoken');
const VendorData = require('./models/mvmodels')
module.exports = function (req, res, next) {
 

    try {
        const authHeader = req.headers['authorization'];
        console.log(authHeader, '9 line jwtmidware authHeader',)
        if (!authHeader) {
            return res.status(400).send('Token Not found');
        }
        if (authHeader) {
            const token = authHeader.split(' ')[1]; // the format is "Bearer <token>"
         
            console.log('fromjwtverify AccessToken : ' + token);

            if (!token) {
                return res.status(400).send('Token Not found');
            }
            let decode = jwt.verify(token, 'vendorSecretKey');
            req.user = decode.user // important it will throw error token expire if do any changes
           async function activity (){
            await VendorData.findByIdAndUpdate(decode.user.id, { lastActivity: Date.now() });
            }
            activity()
            //end

            next();
        }

    }
    catch (err) {
        console.log("from access token expired 403" , err);
        return res.status(403).send('token expired')
    }
}