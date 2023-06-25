const fs = require('fs');
const express = require('express')
const mysql = require('mysql2')
const bodyParser = require('body-parser');
const { PDFDocument } = require('pdf-lib');
const path = require('path')
const expressLayouts = require('express-ejs-layouts')
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const moment = require('moment');
const bcrypt = require('bcrypt');
const app = express()


// Create multer storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

// Create multer upload configuration
const upload = multer({
  storage: storage
});



//buat folder penampung file jika tidak ada
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}


app.set('views',__dirname)
app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs')
app.use('/css', express.static(path.resolve(__dirname, "assets/css")));
app.use('/img', express.static(path.resolve(__dirname, "assets/img")));

app.use(expressLayouts);




const saltRounds = 10;

// middleware untuk parsing request body
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use(express.urlencoded({ extended: true }));
app.use(express.json());


//koneksi database
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'digitalsign_db'
  });

  db.connect((err)=>{
    if(err) throw err
   console.log('db connected successfully!!')
   })

function requireAuth(req, res, next) {
  
    const token = req.cookies.token;
  
    if (!token) {
      res.redirect('/login');
      return;
    }
    
  
    jwt.verify(token, 'secret_key', function(err, decoded) {
      if (err) {
        res.redirect('/login');
        return;
      }
  
      req.user_id = decoded.user_id;
      next();
    });
  }

//GET

   app.get('/register', function (req, res) {
    res.render('register',{
      title : 'Register',
      layout : 'layouts/auth-layout'
    });
})

   app.get('/login', function (req, res) {
    res.render('login',{
      title : 'Login',
      layout : 'layouts/auth-layout'
    });
})

  app.get('/logout', function(req, res) {
    res.clearCookie('token');
    res.redirect('/login');
  });

  app.get('/', requireAuth, function (req, res) {
    if (!req.user_id) {
      res.redirect('/login');
      return;
    }
  
      const usersSql = `SELECT * FROM users`;
      db.query(usersSql, (err, userResult) => {
      if (err) throw err;

      res.render('index', {
        users: userResult,
        title: 'Home',
        layout: 'layouts/main-layout'
      });
    });
  });
  

app.get('/profile', requireAuth, function (req, res) {
  let user_id = req.user_id;
  const selectSql = `SELECT * FROM users WHERE user_id = ${user_id}`;
  db.query(selectSql, (err,userResult)=>{
    if (err) throw err;
      res.render('profile',{
        user: userResult[0],
        title:'Profile',
        layout:'layouts/main-layout'
      })
  })
})

app.get('/req-sign', requireAuth, function (req, res) {
  let user_id = req.user_id;
  const selectUserSql = `SELECT * FROM users WHERE user_id != ${user_id}`;
  db.query(selectUserSql, (err, userResult) => {
    if (err) throw err;
    res.render('req-sign', {
      users: userResult,
      title: 'add document',
      layout: 'layouts/main-layout'
    });
  });
});


  app.get('/signature', function (req, res) {
    res.render('signature',{ 
    title:"signature",
    layout:"layouts/main-layout"
    }) 
})

  app.get('/action-req', function (req, res) {
    res.render('action-req',{ 
    title:"action required",
    layout:"layouts/main-layout"
    }) 
})

app.get('/docs', requireAuth, function (req, res) {
  
    let user_id = req.user_id;

    const receiveSql = `
    SELECT documents.*, signature.*
    FROM documents
    JOIN signature ON documents.document_id = signature.document_id
    WHERE signature.user_id = ${user_id}
    
    `;
    db.query(receiveSql, (err, receivedResult) => {
      if (err) throw err;

      const yourDocs = `
      SELECT *
      FROM documents WHERE documents.user_id = ${user_id}

    `;
      db.query(yourDocs, (err, docResult) => {
        if (err) throw err;

        res.render('docs', {
          documents: receivedResult,
          yourDocs: docResult,
          moment: moment,
          title: 'Docs',
          layout: 'layouts/main-layout'
      });
    });
  });
});

app.get('/download/:document_id', requireAuth, (req, res) => {
  const document_id = req.params.document_id;
    const docSql = 'SELECT * FROM documents WHERE document_id = ?';
    db.query(docSql, [document_id], function(err, docResult) {
      if (err) throw err;
      if (docResult.length === 0) {
        res.status(404).send('Doc not found');
        return;
      }

      const doc = docResult[0];
      const filePath = `uploads/${doc.filename}`;

      res.download(filePath, doc.file_name, function(err) {
        if (err) {
          console.log(err);
          res.status(500).send('Internal server error');
        }
    });
  });
});


//POST

app.post('/register', function (req, res) {
  const { username, password, confirm_password } = req.body;

  // check if username already exists
  const sqlCheck = 'SELECT * FROM users WHERE username = ?';
  db.query(sqlCheck, username, (err, result) => {
    if (err) throw err;

    if (result.length > 0) {
      console.error({ message: 'Username sudah terdaftar', err });
      req.session.errorMessage = 'Username sudah terdaftar';
      return res.redirect('/register');
    }

    if (password !== confirm_password) {
      console.error({ message: 'Password tidak cocok!', err });
      req.session.errorMessage = 'Password tidak cocok!';
      return res.redirect('/register');
    }

    // hash password
    bcrypt.hash(password, saltRounds, function(err, hash) {
      if (err) throw err;

      // insert user to database
      const sqlInsert = 'INSERT INTO users (username, password) VALUES (?, ?)';
      const values = [username, hash];
      db.query(sqlInsert, values, (err, result) => {
        if (err) throw err;
        console.log({ message: 'Registrasi berhasil', values });
        res.redirect('/login');
      });
    });
  });
});

app.post('/login', function (req, res) {
  const { username, password } = req.body;

  const sql = 'SELECT * FROM users WHERE username = ?';
  db.query(sql, [username], function(err, result) {
    if (err) {
      console.error({ message: 'Internal Server Error', err });
      return res.redirect('/login');
    }

    if (result.length === 0) {
      console.error({ message: 'Username atau Password salah!!', err });
      return res.redirect('/login');
    }

    const user = result[0];

    // compare password
    bcrypt.compare(password, user.password, function(err, isValid) {
      if (err) {
        console.error({ message: 'Internal Server Error', err });
        return res.redirect('/login');
      }

      if (!isValid) {
        console.error({ message: 'Username atau Password salah!!', err });
        return res.redirect('/login');
      }

      // generate token
      const token = jwt.sign({ user_id: user.user_id }, 'secret_key');
      res.cookie('token', token, { httpOnly: true });

      console.log({ message: 'Login Success', user });
      return res.redirect('/');
    });
  });
});

app.post('/edit-profile', upload.single('sign_img'), requireAuth, (req, res) => {
  let user_id = req.user_id;
  const { email } = req.body;
  const signImg = req.file ? req.file.filename : null;

  let updateQuery = 'UPDATE users SET email=?';
  let values = [email];

  if (signImg) {
    updateQuery += ', sign_img=?';
    values.push(signImg);
  }

  updateQuery += ' WHERE user_id=?';
  values.push(user_id);

  db.query(updateQuery, values, (err, result) => {
    if (err) {
      throw err;
    }
    console.log('dah update nih !');

    // Copy file to img directory
    if (signImg) {
      const signImgSource = path.join(__dirname, 'uploads', signImg);
      const signImgDestination = path.join(__dirname, 'assets', 'img', signImg);
      fs.copyFileSync(signImgSource, signImgDestination);
    }
    console.log('profil dah update!')
    res.redirect('/profile');
  });
});





app.post('/change-password', requireAuth, (req, res) => {
  const userId = req.user_id;
  const { password, newPassword } = req.body;

  const sql = 'SELECT password FROM users WHERE user_id = ?';
  db.query(sql, [userId], (err, result) => {
    if (err) {console.log('internal error!')}

    const hashedPassword = result[0].password;
    bcrypt.compare(password, hashedPassword, (error, isMatch) => {
      if (error) {console.log('internal error!')}

      if (isMatch) {
        bcrypt.hash(newPassword, saltRounds, (err, hashedNewPassword) => {
          if (err) {{console.log('internal error!')}}

          const updateSql = 'UPDATE users SET password = ? WHERE user_id = ?';
          const values = [hashedNewPassword, userId];
          db.query(updateSql, values , (err, result) => {
            if (err) {{console.log('internal error!')}}
            console.log('password changed!');
            res.redirect('/profile');
          });
        });
      } else {
        console.log('Invalid current password');
        res.redirect('/profile');
      }
    });
  });
});


app.post('/add-req-sign', upload.single('filename'), (req, res) => {
  const { user_id, name, description, jabatan, status } = req.body;
  const filename = req.file ? req.file.filename : null;

  const insertdocumentql = 'INSERT INTO documents (user_id, name, filename, description) VALUES (?, ?, ?, ?)';
  const documentValues = [user_id, name, filename, description];

  db.query(insertdocumentql, documentValues, (err, documentResult) => {
    if (err) {
      throw err;
    }

    console.log('success!');

    const documentId = documentResult.insertId;
    const insertSignatureSql = 'INSERT INTO signature (user_id, document_id, jabatan, status) VALUES (?, ?, ?, ?)';
    const signatureValues = [user_id, documentId, jabatan, status];

    db.query(insertSignatureSql, signatureValues, (err, signatureResult) => {
      if (err) {
        throw err;
      }

      console.log('success!');
      res.redirect('/docs');
    });
  });
});

app.post('/add-your-docs', requireAuth, upload.single('filename'), (req, res) => {
  const user_id = req.user_id;
  const {  name, description } = req.body;
  const filename = req.file ? req.file.filename : null;
  const insertdocumentql = `INSERT INTO documents ( user_id, name, filename, description) VALUES ( ?, ?, ?, ?)`;
  const values = [  user_id, name, filename, description];
  db.query(insertdocumentql, values, (err, result) => {
    if (err) {
      throw err;
    }
    console.log({msg:'inserted!'},values);

    res.redirect('/docs');
  });
});




app.listen(3000,()=>{
    console.log("Listening at port 3000")
  })