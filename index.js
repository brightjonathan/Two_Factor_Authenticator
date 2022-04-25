const express =  require('express')
const speakeasy = require('speakeasy')
const app = express()
const uuid = require('uuid')
const bodyParser = require('body-parser');
const {JsonDB} = require('node-json-db')
const {Config} = require('node-json-db/dist/lib/JsonDBConfig')

// TWO FACTOR AUTHENTICATOR WITH NODE AND POSTMAN

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

//external database
const db = new JsonDB(new Config('myDatabase', true, false, '/'))

app.get('/api', (req, res)=>{
    res.json({ message: 'welcome to two factor authentication'})
})


//user Registration create temp secret
app.post('/api/register', (req, res)=>{
   const id = uuid.v4()
try {
    //new endpoint
    const path = `/user/${id}`
    
    //generating secret code
    const temp_secret = speakeasy.generateSecret()

    //pushing it to the db
    db.push(path, {id, temp_secret})
    res.json({id, secret: temp_secret.base32})
} catch (error) {
    console.log(error)
    res.status(500).json({message: 'Error'})
}
})


//verify token and create secret perm
app.post('/api/verify', (req, res)=>{
    const {token, userId} = req.body
    
    try {
        
        //new endpoint
        const path = `/user/${userId}`
        const user = db.getData(path)

        //verifying the token
        const {base32:secret} = user.temp_secret
        const varified = speakeasy.totp.verify({secret,
        encoding: 'base32',
        token
        });

        //varifying the 
        if(varified){
         db.push(path, {id: userId, secret: user.temp_secret})
         res.json({varified: true})
        }else{
            res.json({varified: false})
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({message: 'Error finding user'})
    }
});


//validate token 
app.post('/api/validate', (req, res)=>{
    const {token, userId} = req.body
    
    try {
        
        //new endpoint
        const path = `/user/${userId}`
        const user = db.getData(path)

        //verifying the token
        const {base32:secret} = user.secret
        const tokenValidates = speakeasy.totp.verify({secret,
        encoding: 'base32',
        token, window: 1
        });

        //varifying the 
        if(tokenValidates){
         res.json({validated: true})
        }else{
            res.json({validated: false})
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({message: 'Error finding user'})
    }
})




const PORT = process.env.PORT || 5000
app.listen(PORT, ()=> console.log('Server running'))