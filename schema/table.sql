CREATE TABLE IF NOT EXISTS users(
    user_id INT AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    PRIMARY KEY (user_id)
);

CREATE TABLE IF NOT EXISTS profiles(
    user_profile_id int AUTO_INCREMENT,
    user_id INT NOT NULL UNIQUE,
    profile_picture VARCHAR(255),
    phone VARCHAR(20),
    date_of_birth DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY(user_profile_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS questions(
    question_id INT AUTO_INCREMENT, 
    user_id INT NOT NULL,
    title VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    tag VARCHAR(100) DEFAULT NULL,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(question_id),
    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_tag (tag)
);

CREATE TABLE IF NOT EXISTS answers(
    answer_id INT AUTO_INCREMENT,
    question_id INT NOT NULL,
    user_id INT NOT NULL,
    answer TEXT NOT NULL,
    PRIMARY KEY(answer_id),
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (question_id) REFERENCES questions(question_id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_user_id (user_id)
);
CREATE TABLE IF NOT EXISTS likes (
    like_id INT AUTO_INCREMENT,
    user_id INT NOT NULL,
    question_id INT NOT NULL,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(like_id),
    UNIQUE(user_id, question_id), 
    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY(question_id) REFERENCES questions(question_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS question_views (
  user_id INT NOT NULL,
  question_id INT NOT NULL,
  viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, question_id),
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
  FOREIGN KEY (question_id) REFERENCES questions(question_id) ON DELETE CASCADE
);
