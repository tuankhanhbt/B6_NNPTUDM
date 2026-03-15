let jwt = require('jsonwebtoken')
let userController = require("../controllers/users");

function normalizeRoleName(roleName) {
    return String(roleName || "").trim().toUpperCase();
}

module.exports = {
    checkLogin: function (req, res, next) {
        try {
            let token;
            if (req.cookies.token) {
                token = req.cookies.token
            }
            else {
                let authorizationToken = req.headers.authorization;
                if (!authorizationToken || !authorizationToken.startsWith("Bearer ")) {
                    res.status(403).send({
                        message: "ban chua dang nhap"
                    })
                    return;
                }
                token = authorizationToken.split(' ')[1];
            }
            let result = jwt.verify(token, 'HUTECH');
            req.userId = result.id;
            next();
        } catch (error) {
            res.status(403).send({
                message: "ban chua dang nhap"
            })
            return;
        }
    },
    checkRole: function (...requiredRole) {
        return async function (req, res, next) {
            try {
                let userId = req.userId;
                let getUser = await userController.FindByID(userId);
                if (!getUser || !getUser.role) {
                    return res.status(403).send({
                        message: "ban khong co quyen"
                    });
                }
                let roleName = normalizeRoleName(getUser.role.name);
                let normalizedRequiredRoles = requiredRole.map(normalizeRoleName);
                if (normalizedRequiredRoles.includes(roleName)) {
                    next()
                } else {
                    res.status(403).send({
                        message: "ban khong co quyen"
                    })
                }
            } catch (error) {
                res.status(403).send({
                    message: "ban khong co quyen"
                })
            }
        }
    }
}
