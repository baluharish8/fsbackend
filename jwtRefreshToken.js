
const jwt = require('jsonwebtoken');
require('dotenv').config();
const adminData = require('./models/admindata')
const googleAdmin = require('./models/googleadmin')
const VendorData = require('./models/mvmodels')


const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);

    const refreshToken = cookies.jwt;
    console.log("refresh page cookie token :", refreshToken)


    let foundUser = await adminData.findOne({ refreshToken: refreshToken });
    if (!foundUser) {
        foundUser = await googleAdmin.findOne({ refreshToken: refreshToken });

    }
    if (!foundUser) {
        foundUser = await VendorData.findOne({ refreshToken: refreshToken });

    }
    console.log("refresh token user from db :", foundUser)
    if (!foundUser) return res.sendStatus(403); //Forbidden 


    jwt.verify(
        refreshToken,
        'refreshVendorSecretKey',
        (err, decoded) => {

            if (err || foundUser.id !== decoded.user.id) {
                console.log("refresh token expired 35 line 403");
                return res.status(403).send('Refresh Token Expired');  //generate token expire
            }else{
                let payload = {
                    user: {
                        id: decoded.user.id
                    }
                }
                const accessToken = jwt.sign(payload, 'vendorSecretKey', { expiresIn: process.env.TOKEN_EXPIRE })
                console.log("AccessToken from refresh : " + accessToken)
                token = accessToken
    
                return res.json({ accessToken })
            }
      

        }
    );

}

module.exports = { handleRefreshToken }