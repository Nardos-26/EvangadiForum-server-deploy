import pool from "../config/databaseConfig.js";
import {users, questions, answers, question_views, likes} from '../schema/table.js'



const createTableIfNotExists = async (tableName, createStatement) => {
    try {
        const connection = await pool.getConnection();
        const [rows] = await connection.query(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?",
            [process.env.DB_NAME || 'evangadi-db', tableName]
        );
        if (rows.length === 0) {
            await connection.query(createStatement);  //Executing CREATE TABLE Statement, Creating The Table
            console.log(`✅ Table ${tableName} created!`);
        } else {
            console.log(`✅ Table ${tableName} already exists, skipping creation.`);
        }
        connection.release();
    } catch (err) {
        console.error(` Error checking/creating table ${tableName}:`, err.message);
        throw err;
    }
};



export const createAllTables = async () => {
  try{

        await createTableIfNotExists('users', users);
        await createTableIfNotExists('questions', questions);
        await createTableIfNotExists('answers', answers);
        await createTableIfNotExists('question_views', question_views);
        await createTableIfNotExists('likes', likes);

        console.log("✅ Database tables initialized!");

  }catch (err) {
    console.error("Error initializing tables:", err.message);
    throw err;
  }
}