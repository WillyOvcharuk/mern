const {Router} = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

//  /api/auth
router.post(
    '/register',
    [
        check('email','Некорректый email').isEmail(),
        check('password','Длина пароля меньше 6 символов').isLength({ min: 6 }),
    ], 
    async (req, res) => {
    try{
        const errors = validationResult(req)
        if(!errors.isEmpty()){
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некоректні дані',
            })
        }
        const {emai, password} = req.body

        const candidate = await User.findOne({ email })

        if(candidate){
            return res.status(400).json({message: 'такий користувач вже існує'})
        }

        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({ email, password: hashedPassword});

        await user.save()

        res.status(201).json({ message: 'New user has been created'})

    }catch(e){
        res.status(500).json({message: 'что-то пошло не так, try again'})
    }
})

//  /api/login
router.post(
    '/login',
    [
        check('email','Ведіть корректый email').normalizeEmail().isEmail(),
        check('password','Введіть пароль').exists(),
    ], 
    async (req, res) => {
    try{
        const errors = validationResult(req)
        if(!errors.isEmpty()){
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некоректні дані при вході в систему',
            })
        }
    const user = await User.findOne({ email })
    
    if(!user){
        return res.status(400).json({ message: 'Користувач не знайдений' })
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if(!isMatch){
        return res.status(400).json({message: 'password is not correct, try again'})
    }

    const token = jwt.sign(
        {userId: user.id},
        config.get('jwtSecret'),
        {expiresIn: '1h'}
    )

    res.json({token, userId: user.id})

    }catch(e){
        res.status(500).json({message: 'что-то пошло не так, try again'})
    }
})
module.exports = router