const mysql = require("mysql");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { promisify } = require('util');

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE
});

const transporter = nodemailer.createTransport({
  host: 'live.smtp.mailtrap.io',
  port: 587,
  secure: false, 
  auth: {
    user: 'anhntnse181829@fpt.edu.vn',
    pass: process.env.EMAIL_PASSWORD,
  }
});

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Kiểm tra xem email và password có được cung cấp không
    if (!email || !password) {
      return res.status(400).render('login', {
        message: 'Please provide an email and password',
      });
    }

    // Truy vấn database để lấy thông tin người dùng
    db.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
      if (error) {
        console.error('Database query error: ', error);
        return res.status(500).render('login', {
          message: 'Something went wrong. Please try again later.',
        });
      }

      // Kiểm tra nếu không tìm thấy người dùng
      if (results.length === 0) {
        return res.status(401).render('login', {
          message: 'Email or Password is incorrect',
        });
      }

      // Kiểm tra mật khẩu
      const user = results[0];
      const isPasswordCorrect = await bcrypt.compare(password, user.password);

      if (!isPasswordCorrect) {
        return res.status(401).render('login', {
          message: 'Email or Password is incorrect',
        });
      }

      // Tạo JWT token
      const id = user.user_id;
      const token = jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
      });

      console.log('The token is: ' + token);
      // Thiết lập tùy chọn cookie
      const cookieOptions = {
        expires: new Date(
          Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
        ),
        httpOnly: true, // Bảo vệ cookie chỉ được truy cập qua HTTP
        secure: process.env.NODE_ENV === 'production', // Chỉ gửi cookie qua HTTPS nếu đang ở production
      };

      // Gửi cookie và chuyển hướng
      res.cookie('jwt', token, cookieOptions);
      return res.status(200).redirect('/');
    });
  } catch (error) {
    console.error('Login error: ', error);
    return res.status(500).render('login', {
      message: 'Something went wrong. Please try again later.',
    });
  }
};

exports.register = (req, res) => {
  const { username, fullname, email, password, passwordConfirm } = req.body;

  if (!username || !fullname || !email || !password || !passwordConfirm) {
    return res.render('register', {
      message: 'Please fill in all fields'
    });
  }

  if (password !== passwordConfirm) {
    return res.render('register', {
      message: 'Passwords do not match'
    });
  }

  db.query('SELECT email FROM users WHERE email = ?', [email], async (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).render('register', {
        message: 'Internal server error. Please try again later.'
      });
    }

    if (results.length > 0) {
      return res.render('register', {
        message: 'That email is already in use'
      });
    }

    db.query('SELECT username FROM users WHERE username = ?', [username], async (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).render('register', {
          message: 'Internal server error. Please try again later.'
        });
      }

      if (results.length > 0) {
        return res.render('register', {
          message: 'That username is already in use'
        });
      }

      const hashedPassword = await bcrypt.hash(password, 8);

      db.query('INSERT INTO users SET ?', { username, fullname, email, password: hashedPassword }, (error, results) => {
        if (error) {
          console.error(error);
          return res.status(500).render('register', {
            message: 'Internal server error. Please try again later.'
          });
        } else {
          return res.render('register', {
          message: 'User registered'
          });
        }
      });
    });
  });
};

exports.isLoggedIn = async (req, res, next) => {
  console.log("user is")
  // console.log(req.cookies);
  if( req.cookies.jwt) {
    try {
      //1) verify the token
      const decoded = await promisify(jwt.verify)(req.cookies.jwt,
      process.env.JWT_SECRET
      );

      console.log("decode.id", decoded);

      //2) Check if the user still exists
      db.query('SELECT * FROM users WHERE user_id = ?', [decoded.id], (error, result) => {
        if (error || !result || result.length === 0) {
          return next();
        }
        

        req.user = result[0];
        console.log(req.user);
        return next();

      });
    } catch (error) {
      console.log(error);
      return next();
    }
  } else {
    next();
  }
}

exports.logout = async (req, res) => {
  res.cookie('jwt', 'logout', {
    expires: new Date(Date.now() + 2*1000),
    httpOnly: true
  });

  res.status(200).redirect('/');
}

exports.forgotpassword = async (req, res) => {
  const { email } = req.body;

  // Step 1: Check if user exists in the database
  const sql = `SELECT * FROM users WHERE email=?`;
  db.query(sql, [email], async (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    if (result.length === 0) {
      return res.status(404).json({ message: 'No user found with that email' });
    }

    const user = result[0];

    // Step 2: Generate a JWT token (expires in 1 hour)
    const token = jwt.sign({id: user.user_id }, 'your_jwt_secret', { expiresIn: '1h' });

    // Step 3: Generate a reset link
    const resetLink = `http://localhost:3000/resetpassword/${token}`;
    console.log(token);

    // Step 4: Configure the email options
    const mailOptions = {
      to: email,
      from: 'anhntnse181829@fpt.edu.vn',
      subject: 'Password Reset Request',
      text: `You requested a password reset. Please click the link to reset your password: ${resetLink}\n
             This link will expire in 1 hour. If you didn't request this, please ignore this email.`
    };

    // Step 5: Send the email
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        return res.status(500).json({ message: 'Error sending email' });
      }
      res.status(200).json({ message: 'Password reset email sent successfully', info });
    });
  });
};

// Reset Password Function
exports.resetpassword = (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  // Verify JWT token
  jwt.verify(token, 'your_jwt_secret', (err, decoded) => {
    if (err) {
      return res.status(400).json({ message: 'Token is invalid or expired' });
    }

    const userId = decoded.id;

    // Hash the new password
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Update the password in the database
    const sql = `UPDATE users SET password=? WHERE id=?`;
    connection.query(sql, [hashedPassword, userId], (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      res.status(200).json({ message: 'Password updated successfully' });
    });
  });
};
