const jwt = require('jsonwebtoken');
const VendorData = require('./models/mvmodels')
module.exports = function (req, res, next) {
    // console.log(req.header+"hhh")
    // console.log(req.headers['cookie']);

    try {
        const authHeader = req.headers['authorization'];
        console.log(authHeader, '9 line jwtmidware authHeader',)
        if (!authHeader) {
            return res.status(400).send('Token Not found');
        }
        if (authHeader) {
            const token = authHeader.split(' ')[1]; // Assuming the format is "Bearer <token>"
            // Now you have the token, you can verify it or perform any necessary authentication logic
            // let token = req.header('vendor-token');
            console.log('fromjwtverify AccessToken : ' + token);

            if (!token) {
                return res.status(400).send('Token Not found');
            }
            let decode = jwt.verify(token, 'vendorSecretKey');
            req.user = decode.user // important it will throw error token expire if do any changes
            console.log(decode.user, req.user, 'jwtmid req, decode user')

            console.log(decode.user.id)
            // console.log(JSON.stringify(decode, null, 2)); //working
            //inserting last activity start
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