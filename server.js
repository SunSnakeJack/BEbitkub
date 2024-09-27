var express = require('express');
var cors = require('cors');
var app = express();
var bodyParser = require('body-parser');
var jsonParser = bodyParser.json();
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = 'backend-Test-2024';
app.use(express.json());
app.use(bodyParser.json());

app.use(cors());

const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'projectbitkub' 
});

// Middleware สำหรับตรวจสอบ JWT Token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ status: 'forbidden', message: 'No token provided.' });

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ status: 'forbidden', message: 'Please login' });
        console.log('Decoded token', user);

        // เพิ่มข้อมูล user ลงใน req.user เพื่อให้เข้าถึงได้ภายหลัง
        req.user = { userId: user.userId, firstname: user.firstname, lastname: user.lastname, disabilitytype: user.disabilitytype, caregiverId: user.caregiverId };
        next();
    });
}

// Login Route โดยใช้ userId และ password
app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE userId=?', // เปลี่ยนเป็น userId แทน email
        [req.body.userId], // ใช้ userId ในการค้นหา
        function (err, users, fields) {
            if (err) { 
                res.json({ status: 'error', message: err }); 
                return; 
            }
            if (users.length == 0) { 
                res.json({ status: 'error', message: 'no user found' }); 
                return; 
            }
            
            // เปรียบเทียบรหัสผ่านกับ hashed password ในฐานข้อมูล
            bcrypt.compare(req.body.password, users[0].password, function (err, isLogin) {
                if (isLogin) {
                    // สร้าง token ที่มีข้อมูล userId, firstname, lastname, disabilitytype, caregiverId
                    const accessToken = jwt.sign(
                        { 
                            userId: users[0].userId, 
                            firstname: users[0].firstname, 
                            lastname: users[0].lastname, 
                            disabilitytype: users[0].disabilitytype,
                            caregiverId: users[0].caregiverId 
                        },
                        secret,
                        { expiresIn: '1h' }
                    );
                    res.json({ status: 'ok', message: 'login success', accessToken: accessToken });
                } else {
                    res.json({ status: 'error', message: 'login failed' });
                }
            });
        }
    );
});






app.post('/register', jsonParser, function (req, res, next) {
    // ทำการ hash password ก่อนบันทึก
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        if (err) {
            res.json({ status: 'error', message: 'Hashing failed' });
            return;
        }

        // บันทึกข้อมูลลงในตาราง users
        connection.execute(
            'SELECT * FROM users WHERE userId = ?',
            [req.body.userId],
            function (err, results) {
                if (err) {
                    res.json({ status: 'error', message: err });
                    return;
                }
                if (results.length > 0) {
                    return res.json({ status: 'error', message: 'User ID already exists' });
                }
        
                // ถ้า userId ไม่ซ้ำกัน ให้ทำการแทรกข้อมูล
                connection.execute(
                    'INSERT INTO users (userId, password, firstname, lastname, disabilitytype, caregiverId) VALUES (?, ?, ?, ?, ?, ?)',
                    [
                        req.body.userId,
                        hash,
                        req.body.firstname,
                        req.body.lastname,
                        req.body.disabilitytype,
                        req.body.caregiverId
                    ],
                    function (err, results) {
                        if (err) {
                            res.json({ status: 'error', message: err });
                            return;
                        }
                        res.json({ status: 'ok', message: 'Register successfully' });
                    }
                );
            }
        );
        
    });
});


// เพิ่มฟังก์ชันเพื่อเข้าถึงข้อมูลผู้ใช้ (ตัวอย่าง)
app.get('/profile', authenticateToken, (req, res) => {
    let disabilityMessage;

    // ตรวจสอบ disabilitytype และกำหนดข้อความที่ต้องการแสดง
    switch (req.user.disabilitytype) {
        case 'blind person':
            disabilityMessage = 'You are a blind person.';
            break;
        case 'deaf person':
            disabilityMessage = 'You are a deaf person.';
            break;
        case 'mute person':
            disabilityMessage = 'You are a mute person.';
            break;
        default:
            disabilityMessage = 'Disability type not specified.';
    }

    // ส่งข้อมูลผู้ใช้พร้อมข้อความ disability
    res.json({
        status: 'ok',  // เพิ่ม status
        user: {        // รวมข้อมูลผู้ใช้ใน object 'user'
            firstname: req.user.firstname,
            lastname: req.user.lastname,
            caregiverId: req.user.caregiverId,
            message: disabilityMessage // เพิ่มข้อความที่เกี่ยวข้อง
        }
    });
});


// เริ่มเซิร์ฟเวอร์
app.listen(3001, () => {
    console.log('Server is running on port 3001');
});
