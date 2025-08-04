import { updatePasswordHashUser, searchLoginUserById, searchUserLogin } from './users.controller.js'
import { hashPassword, verifyPassword } from '../../utils/auth/handle-password.js'
import { responseQueries } from '../../common/enum/queries/response.queries.js'
import { responseJWT } from '../../common/enum/jwt/response.jwt.js'
import { variablesDB } from '../../utils/params/const.database.js'
import { generateToken } from '../../utils/token/handle-token.js'
import { sendEmailFunction } from '../../lib/api/email.api.js'
import getConnection from '../../database/connection.mysql.js'
import { getRoleUser } from './role.controller.js'

export const getUserInfo = async (req, res) => {
    const conn = await getConnection()
    const db = variablesDB.academy
    const { id_user } = req.params
    const select = await conn.query(`SELECT * FROM ${db}.login_users WHERE id_user = ?;`, [id_user])
    if (!select) return res.json(responseQueries.error({ message: 'Error obteniendo el usuario' }))
    return res.json(responseQueries.success({ data: select[0] }))
}

export const getRecoverPaswordUser = async (req, res) => {
    const { email } = req.body
    if (!email) {
        return res.status(400).json(responseQueries.error({ message: 'Email is required', status: 400, token: null, user: null }))
    }
    const userExist = await searchUserLogin({ username: email })
    if (userExist.error) {
        res.json(responseJWT.error({ message: userExist.message, status: userExist.status, token: null, user: null }))
        return
    }
    const role = await getRoleUser(userExist.data[0].id_user);
    if (role.error) {
        res.json(responseJWT.error({ message: role.message, status: role.status, token: null, user: null }))
        return
    }
    const tokenUsername = await generateToken({
        sub: userExist.data[0].id_user,
        username: userExist.data[0].username
    })
    const tokenPassword = await generateToken({
        sub: userExist.data[0].id_user,
        password: userExist.data[0].password
    })
    const tokenRole = await generateToken({
        sub: userExist.data[0].id_user,
        role: role.data[0].description_role
    })
    const sendMail = await sendEmailFunction({ name: '', username: tokenUsername, password: tokenPassword, email: email, type: 'recover_password', role_user: tokenRole })
    return res.json(responseQueries.success({ message: "Success solitude recover", data: sendMail }));
}

// export const updateUserLoginById = async (req, res) => {
//     const { user_id, username, passwordNew, passwordOld, verify } = req.body

//     const userExist = await searchLoginUserById({ id: user_id })
//     if (userExist.error) {
//         return res.json(responseQueries.error({
//             message: userExist.message,
//             status: userExist.status,
//             token: null,
//             user: null
//         }))
//     }

//     const userPasswordHash = userExist.data[0].password

//     const isPasswordCorrect = await verifyPassword(passwordOld, userPasswordHash)
//     if (!isPasswordCorrect) {
//         return res.status(400).json(responseQueries.success({ message: "Contraseña incorrecta" }))
//     }

//     const passwordHash = await hashPassword({ password: passwordNew })

//     const updatePassword = await updatePasswordHashUser({
//         id: user_id,
//         password: passwordHash.password,
//         verify: !verify
//     })

//     if (!updatePassword) {
//         return res.status(400).json(responseQueries.success({ message: "Error al actualizar la contraseña" }))
//     }

//     return res.status(200).json(responseQueries.success({ message: "Contraseña actualizada correctamente" }))
// }

export const updateUserLoginById = async (req, res) => {
    const { user_id, username, passwordNew, passwordOld, verify } = req.body
    const userExist = await searchLoginUserById({ id: user_id })
    if (userExist.error) {
        res.json(responseQueries.error({ message: userExist.message, status: userExist.status, token: null, user: null }))
        return
    }
    const looksLikeHash = passwordOld.startsWith('$2b$') && passwordOld.length > 50
    if(passwordOld !== userExist.data[0].password && !looksLikeHash) {
        const verifyPasswordOld = await verifyPassword(passwordOld, userExist.data[0].password);
        if (!verifyPasswordOld && userExist.data[0].password !== passwordOld) {
            return res.status(400).json(responseQueries.success({ message: "Contraseña incorrecta" }))
        }
    }
    const passwordHash = await hashPassword({ id: user_id, username: username, email: username, password: passwordNew })
    const updatePassword = await updatePasswordHashUser({ id: user_id, password: passwordHash.password, verify: !verify })
    if (!updatePassword) {
        return res.status(400).json(responseQueries.success({ message: "Error al actualizar la contraseña" }))
    }
    return res.status(200).json(responseQueries.success({ message: "Contraseña actualizada correctamente" }))
}