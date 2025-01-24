require('dotenv').config();

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const db = require('./config/db');
const cors = require('cors');
const cron = require('node-cron');
const { read } = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const verifyToken = require('./middleware/verifyToken');
const fs = require('fs');``
const https = require('https');

const ExcelJS = require('exceljs');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cors());

let cronInterval = `*/${process.env.CONFIG_FETCH_INTERVAL} * * * *`;
let appList = process.env.CONFIG_APPLICATIONS.split(',');
let locations = process.env.CONFIG_LOCATIONS.split(',');
let actions = process.env.CONFIG_ACTIONS.split(',');
let scheduleTask;
let isTaskRunning = false;
let totalJobs = {}
let totalJobsDone = {}

SECRET_KEY = process.env.JWT_SECRET;
const MAX_LOGIN_ATTEMPTS = 3;
const COOLDOWN_PERIOD = 15 * 60 * 1000; //15 minutes

// https
// const agent = new https.Agent({
//   cert: fs.readFileSync('/etc/nginx/ssl/D1UJHSHOSTLV001.crt'),
//   key: fs.readFileSync('/etc/nginx/ssl/D1UJHSHOSTLV001.key'),
//   rejectUnauthorized: false // Ensures SSL verification
// });

// http
const agent = new https.Agent({
  rejectUnauthorized: false
})

function parseDate(time) {
  const year = time.slice(0, 4);
  const month = time.slice(4, 6) - 1; // Month is zero-based in Date
  const day = time.slice(6, 8);
  const hours = time.slice(8, 10);
  const minutes = time.slice(10, 12);
  const seconds = time.slice(12, 14);

  return new Date(year, month, day, hours, minutes, seconds);
}

function formatDuration(interval) {
  const hours = interval.hours || 0;
  const minutes = interval.minutes || 0;
  const seconds = interval.seconds || 0;
  
  return `${hours}h ${minutes}m ${seconds}s`;
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
};

async function startTaskUpdateAllData() {
  scheduleTask = cron.schedule(cronInterval, async () => {
    isTaskRunning = true;
    const currentDate = new Date();
  
    console.log('Fetching at:', currentDate.toString());
    console.log(cronInterval);
    try {
      await axios.get(`${process.env.CURRENT_BASE_URL}/api/update-all-v2`, {
        httpsAgent: agent
      });
      console.log('Update successful');
    } catch (error) {
      console.error('Error hitting /api/update-all-v2:', error.message);
  
      //generate token when fail
      try {
        await axios.post(`${process.env.CURRENT_BASE_URL}/api/generate-token`, {
          username: `${process.env.CTM_USERNAME}`,
          password: `${process.env.CTM_PASSWORD}`
        }, {
          httpsAgent: agent
        });
        console.log('Successfully generate token');
        await axios.get(`${process.env.CURRENT_BASE_URL}/api/update-all-v2`);
        console.log('Successfully retry update');
      } catch (errorRetry) {
        console.log('Error when generate token and retry update:', errorRetry.message);
      }
    } finally {
      isTaskRunning = false;
    }
  });
};

function restartTask() {
  if (scheduleTask) {
    if (isTaskRunning) {
      console.log('Waiting task to finish...');
      const interval = setInterval(() => {
        if (!isTaskRunning) {
          clearInterval(interval);
          scheduleTask.stop();
          startTaskUpdateAllData();
        }
      }, 500);
    } else {
      scheduleTask.stop();
      startTaskUpdateAllData();
    }
  } else {
    startTaskUpdateAllData();
  }
}

cron.schedule('0 0 1 * *', () => {
  console.log('Running the database cleanup task...');
  deleteOldRecords();
});

async function deleteOldRecords() {
  try {
    await db.query(`
      DELETE FROM jobs
      WHERE created_at < NOW() - INTERVAL '3 months'
    `);
    console.log('Old data (more than 3 months) deleted from jobs table successfully');

    await db.query(`
      DELETE FROM folders
      WHERE created_at < NOW() - INTERVAL '3 months'
    `);
    console.log('Old data (more than 3 months) deleted from folders table successfully');
  } catch (error) {
    console.error('Error deleting old data:', error);
  }
};

app.get('/api/check', async (req, res) => {
  const now = new Date();
  const utcOffset = now.getTimezoneOffset(); // Offset in minutes
  const localTime = now.toString(); // Local time string
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone; // Time zone string
  const tzVariable = process.env.TZ || 'No TZ variable set'; // Environment TZ variable
  const result = await db.query('SELECT NOW() AS current_date');
  const currentDateFromDB = result.rows[0].current_date; // Get the current date

  res.json({
    config: {
      CURRENT_BASE_URL: `${process.env.CURRENT_BASE_URL}`,
      CTM_BASE_URL: `${process.env.CTM_BASE_URL}`,
      CTM_NAME: `${process.env.CTM_NAME}`,
      CTM_USERNAME: `${process.env.CTM_USERNAME}`,
      CONFIG_APPLICATIONS: `${process.env.CONFIG_APPLICATIONS}`,
      CONFIG_LOCATIONS: `${process.env.CONFIG_LOCATIONS}`,
      CONFIG_ACTIONS: `${process.env.CONFIG_ACTIONS}`,
      currentLocalTime: localTime,
      utcOffset: utcOffset,
      currentTimeZone: timeZone,
      tzVariable: tzVariable,
      currentDateFromDB: currentDateFromDB
    }
  });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const user = result.rows[0];
    const currentTime = new Date();

    if (currentTime > new Date(user.locked_until) ) {
      await db.query('UPDATE users set locked_until = NULL, failed_attempts = 0 where username = $1', [username]);
    } else {
      const remainingTimeMs = new Date(user.locked_until) - currentTime; // time difference in milliseconds
      const remainingMinutes = Math.ceil(remainingTimeMs / (60 * 1000)); // convert to minutes

      return res.status(403).json({ 
        message: `Account is locked. Try again after ${remainingMinutes} minutes` 
      });
    }

    const hashedPassword = hashPassword(password);

    if (user.password !== hashedPassword) {
      await db.query(`UPDATE users SET failed_attempts = ${user.failed_attempts} + 1 WHERE username = $1`, [username]);

      if (user.failed_attempts > MAX_LOGIN_ATTEMPTS) {
        const lockedUntil = new Date(currentTime.getTime() + COOLDOWN_PERIOD);
        const remainingTimeMs = lockedUntil - currentTime; // time difference in milliseconds
        const remainingMinutes = Math.ceil(remainingTimeMs / (60 * 1000)); // convert to minutes

        await db.query('UPDATE users SET locked_until = $1 where username = $2', [lockedUntil, username]);
        return res.status(403).json({ 
          message: `Too many failed attempts. Try again after ${remainingMinutes} minutes` 
        });
      }

      return res.status(401).json({ message: 'Invalid username or password' });
    }

    await db.query(`UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = $1`, [username]);

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h'});

    res.status(200).json({ token: token });
  } catch (error) {
    console.error(error);
    res.status(500).json({error});
  }
});

app.get('/api/config', (req, res) => {
  res.status(200).json({
    config: {
      backendBaseUrl: process.env.CURRENT_BASE_URL,
      ctmBaseUrl: process.env.CTM_BASE_URL,
      ctmName: process.env.CTM_NAME,
      ctmUsername: process.env.CTM_USERNAME,
      applications: process.env.CONFIG_APPLICATIONS.split(','),
      fetchInterval: process.env.CONFIG_FETCH_INTERVAL
    }
  });
});

app.put('/api/config', verifyToken, (req, res) => {
  const {
    currentBaseUrl,
    ctmBaseUrl,
    ctmName,
    ctmUsername,
    ctmPassword,
    applications,
    fetchInterval,
  } = req.body;
  const oldCtmPassword = process.env.CTM_PASSWORD;
  
  if (!fetchInterval || isNaN(fetchInterval) || fetchInterval < 1 || fetchInterval > 59) {
    return res.status(400).json({ error: 'fetchInterval must be an integer between 1 and 59 minutes.' });
  }
  
  try {
    process.env.CTM_PASSWORD = ctmPassword;

    if (!ctmPassword) {
      process.env.CTM_PASSWORD = oldCtmPassword;
    }

    process.env.CURRENT_BASE_URL = currentBaseUrl;
    process.env.CTM_BASE_URL = ctmBaseUrl;
    process.env.CTM_NAME = ctmName;
    process.env.CTM_USERNAME = ctmUsername;
    process.env.CONFIG_APPLICATIONS = applications.join(',');
    process.env.CONFIG_FETCH_INTERVAL = fetchInterval;

    cronInterval = `*/${process.env.CONFIG_FETCH_INTERVAL} * * * *`;
    appList = process.env.CONFIG_APPLICATIONS.split(',');

    process.env.TOKEN = '';
    restartTask();
    res.status(201).json('Config Updated');
  } catch (error) {
    res.status(500).send('Error While Updating Config:', error)
  }
});

app.get('/api/config/check', verifyToken, async (req, res) => {
  let token;
  let resultCheckAuth;
  let resultCheckCTM;

  try {
    await axios.get(`${process.env.CTM_BASE_URL}/automation-api`,{
      timeout: 10000,
      httpsAgent: agent
    });
    resultCheckCTM = true;
  } catch (error) {
    return res.status(200).json({
      checkAuth: false,
      checkCTM: false
    });
  }

  try {
    const checkAuth = await axios.post(`${process.env.CTM_BASE_URL}/automation-api/session/login`, {
      username: process.env.CTM_USERNAME,
      password: process.env.CTM_PASSWORD
    }, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 10000,
      httpsAgent: agent // allows self-signed certificates
    });
    token = checkAuth.data.token;
    resultCheckAuth = true;
  } catch (error) {
    resultCheckAuth = false;
  }

  res.status(200).json({
    checkCTM: resultCheckCTM,
    checkAuth: resultCheckAuth
  });
});

app.post('/api/generate-token', async (req, res) => {
  const { username, password } = req.body;
  try {
    const response = await axios.post(`${process.env.CTM_BASE_URL}/automation-api/session/login`, {
      username, password
    }, {
      headers: {
        'Content-Type': 'application/json'
      },
      httpsAgent: agent // allows self-signed certificates
    });
    process.env.TOKEN = response.data.token;
    res.status(200).send(response.data.token);
  } catch (error) {
    res.status(500).send(error)
  }
});

app.get('/api/update-all-v2', async (req, res) => {
  console.log('appList:', appList)

  try {
    console.log('Updating data Control-M...');
    const response = await axios.get(`
        ${process.env.CTM_BASE_URL}/automation-api/run/jobs/status?ctm=${process.env.CTM_NAME}&deleted=false&limit=10000
      `, {
        headers: {
          'Authorization': `Bearer ${process.env.TOKEN}`
        },
        // allows self-signed certificates
        httpsAgent: agent 
      });
    console.log('Control-M data:', response.data.statuses?.length, 'item');

    const statuses = response.data.statuses || [];

    const tmpApps = [];
    const tmpFolders = [];
    const tmpJobs = [];

    for (const item of statuses) {
      //destruct variable from single object
      const { 
        name, folder, type, status, held, deleted, cyclic, startTime, endTime, 
        estimatedStartTime, estimatedEndTime, orderDate, description, application, 
        subApplication 
      } = item;

      //only for prefix folder name 'BDISOA_'
      if (folder.includes('BDISOA_')) {
        //store object (app) into temporary app if doesnt exist in temporary app
        if (!tmpApps.some(app => app.application === application)) {
          tmpApps.push({ 'application': application });
        }
        //store object (folder and job) when citeria match and in folder with prefix 'APP_LOC' 
        if (folder.includes('APP_LOC')) {
          if (!tmpFolders.some(fld => fld.folder === folder && fld.startTime)) {
            tmpFolders.push({
              'folder': folder, 'status': status, 
              'orderDate': orderDate, 'startTime': startTime, 'endTime': endTime, 
              'estimatedStartTime': estimatedStartTime, 'estimatedEndTime': estimatedEndTime, 
              'application': application 
            });
          }
          if (['Command', 'Dummy', 'Job'].includes(type) && !tmpJobs.some(job => 
            job.name === name && job.startTime === startTime)) {
              tmpJobs.push({
                'name': name, 'type': type, 'status': status, 'orderDate': orderDate, 
                'startTime': startTime, 'endTime': endTime, 'application': application, 
                'subApplication': subApplication, 'folder': folder
              });
          }
        }

        //loop through listed app, location, action and store into temporary folder and job
        for (const appName of appList) {
          for (const location of locations) {
            for (const action of actions) {
              if (folder.includes(`${action}_${appName}_To_${location}`)) {
                if (type === 'Folder' && !folder.includes('/')) {
                  tmpFolders.push({
                    'folder': folder, 'status': status, 
                    'orderDate': orderDate, 'startTime': startTime, 'endTime': endTime, 
                    'estimatedStartTime': estimatedStartTime, 'estimatedEndTime': estimatedEndTime, 
                    'application': application
                  });
                }
                //remove some if allow redundant job name in tmpJobs but wont affect db because db check by orderdate
                if (['Command', 'Dummy', 'Job'].includes(type)) {
                    tmpJobs.push({
                      'name': name, 'type': type, 'status': status, 'orderDate': orderDate, 
                      'startTime': startTime, 'endTime': endTime, 'application': application, 
                      'subApplication': subApplication, 'folder': folder
                    });
                }
              }
            }
          }
        }
      }
    }
    console.log('tmpApps:', tmpApps.length);
    console.log(tmpFolders.length, 'tmpFolders:', tmpFolders);
    console.log('tmpJobs:', tmpJobs.length);

    const escapeString = (str) => {
      return str.replace(/'/g, "''");
    };

    // Deduplicate folders based on the unique constraint, keeping the latest start_time
    // Use parsedDate() because from CTM API is startTime: '20250120085240'
    const uniqueFolders = Array.from(
      tmpFolders
        .sort((a, b) => parseDate(b.startTime) - parseDate(a.startTime)) // Sort by start_time descending
        .reduce((map, folder) => {
          const key = `${folder.folder}-${folder.orderDate}`;
          if (!map.has(key) || parseDate(folder.startTime) > parseDate(map.get(key).startTime)) {
            map.set(key, folder);
          }
          return map;
        }, new Map())
        .values()
    );

    // Deduplicate jobs based on the unique constraint, keeping the latest start_time
    const uniqueJobs = Array.from(
      tmpJobs
        .sort((a, b) => parseDate(b.startTime) - parseDate(a.startTime)) // Sort by start_time descending
        .reduce((map, job) => {
          const key = `${job.name}-${job.orderDate}-${job.folder}`;
          if (!map.has(key) || parseDate(job.startTime) > parseDate(map.get(key).startTime)) {
            map.set(key, job);
          }
          return map;
        }, new Map())
        .values()
    );

    console.log('uniqueFolders', uniqueFolders);
    
    const insertOrUpdateFolders = `
      INSERT INTO folders (
        name, status, order_date, start_time, end_time, estimated_start_time,
        estimated_end_time, application
      ) VALUES ${uniqueFolders.map(folder => `(
          '${escapeString(folder.folder)}',
          '${escapeString(folder.status)}',
          ${folder.orderDate ? `TO_TIMESTAMP('${folder.orderDate}', 'YYMMDD') AT TIME ZONE 'Asia/Jakarta'` 
            : `TO_TIMESTAMP('19990101', 'YYMMDD') AT TIME ZONE 'Asia/Jakarta'`}, 
          ${folder.startTime ? `TO_TIMESTAMP('${folder.startTime}', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'` 
            : `TO_TIMESTAMP('19990101000000', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'`},
          ${folder.endTime ? `TO_TIMESTAMP('${folder.endTime}', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'` 
            : `TO_TIMESTAMP('19990101000000', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'`},
          ${folder.estimatedStartTime && folder.estimatedStartTime[0] !== 'NO_TIME' 
            ? `TO_TIMESTAMP('${folder.estimatedStartTime[0]}', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'` 
            : `TO_TIMESTAMP('19990101000000', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'`}, 
          ${folder.estimatedEndTime && folder.estimatedEndTime[0] !== 'NO_TIME' 
            ? `TO_TIMESTAMP('${folder.estimatedEndTime[0]}', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'` 
            : `TO_TIMESTAMP('19990101000000', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'`},
          '${escapeString(folder.application)}'
        )`).join(', ')}
      ON CONFLICT (name, order_date)
      DO UPDATE SET 
        status = EXCLUDED.status,
        start_time = CASE 
            WHEN EXCLUDED.start_time > folders.start_time THEN EXCLUDED.start_time
            ELSE folders.start_time
          END,
        end_time = CASE 
            WHEN EXCLUDED.end_time > folders.end_time THEN EXCLUDED.end_time
            ELSE folders.end_time
          END,
        estimated_start_time = CASE 
            WHEN EXCLUDED.estimated_start_time > folders.estimated_start_time THEN EXCLUDED.estimated_start_time
            ELSE folders.estimated_start_time
          END,
        estimated_end_time = CASE 
            WHEN EXCLUDED.estimated_end_time > folders.estimated_end_time THEN EXCLUDED.estimated_end_time
            ELSE folders.estimated_end_time
          END
    `

    const insertOrUpdateJobs = `
      INSERT INTO jobs (
        name, type, status, order_date, start_time, end_time, application, sub_application, folder
      ) VALUES ${uniqueJobs.map(job => `(
          '${escapeString(job.name)}',
          '${escapeString(job.type)}',
          '${escapeString(job.status)}',
          ${job.orderDate ? `TO_TIMESTAMP('${job.orderDate}', 'YYMMDD')` 
            : `TO_TIMESTAMP('19990101', 'YYMMDD') AT TIME ZONE 'Asia/Jakarta'`}, 
          ${job.startTime ? `TO_TIMESTAMP('${job.startTime}', 'YYYYMMDDHH24MISS')` 
            : `TO_TIMESTAMP('19990101000000', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'`}, 
          ${job.endTime ? `TO_TIMESTAMP('${job.endTime}', 'YYYYMMDDHH24MISS')` 
            : `TO_TIMESTAMP('19990101000000', 'YYYYMMDDHH24MISS') AT TIME ZONE 'Asia/Jakarta'`}, 
          '${escapeString(job.application)}', 
          '${escapeString(job.subApplication)}',
          '${escapeString(job.folder)}'
        )`).join(', ')}
      ON CONFLICT (name, order_date, folder)
      DO UPDATE SET
        status = EXCLUDED.status,
        start_time = CASE 
            WHEN EXCLUDED.start_time > jobs.start_time THEN EXCLUDED.start_time
            ELSE jobs.start_time
          END,
        end_time = CASE 
            WHEN EXCLUDED.end_time > jobs.end_time THEN EXCLUDED.end_time
            ELSE jobs.end_time
          END
    `
    if (tmpFolders.length > 0) {
      console.log('Insert or updating Folders');
      console.log('SQL Query for Folders:', insertOrUpdateFolders);
      await db.query(insertOrUpdateFolders);
    } else {
      console.log('Temporary folders is empty, nothing to insert or update')
    }

    if (tmpJobs.length > 0) {
      console.log('Insert or updating jobs');
      // console.log(insertOrUpdateJobs);
      await db.query(insertOrUpdateJobs);
    } else {
      console.log('Temporary jobs is empty, nothing to insert or update')
    }
    
    res.status(200).json({
      totalApps: tmpApps.length,
      totalFolders: tmpFolders.length,
      totalJobs: tmpJobs.length,
      varApps: tmpApps,
      varFolders: tmpFolders,
      varJobs: tmpJobs
    });
  } catch (error) {
    console.log('error: ', error.message, error.stack)
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/jobs-folders/:app', async (req, res) => {
  const application = req.params.app;
  try {
    const jobs = await db.query(`
      SELECT folder, name, type, status,
        NULLIF(start_time, '1999-01-01 00:00:00') AS start_time,
        NULLIF(end_time, '1999-01-01 00:00:00') AS end_time,
        order_date, application, sub_application
      FROM jobs WHERE application LIKE $1 
      AND created_at >= DATE_TRUNC('month', CURRENT_DATE)
      ORDER BY start_time DESC NULLS LAST
      `, [`%${application}%`]);

    const folders = await db.query(`
      SELECT name, application, status, 
      NULLIF(start_time, '1999-01-01 00:00:00') AS start_time, 
      NULLIF(end_time, '1999-01-01 00:00:00') AS end_time, 
      NULLIF(estimated_start_time, '1999-01-01 00:00:00') AS estimated_start_time, 
      NULLIF(estimated_end_time, '1999-01-01 00:00:00') AS estimated_end_time
      FROM folders
      WHERE application LIKE $1 
      AND created_at >= DATE_TRUNC('month', CURRENT_DATE)
      AND name NOT LIKE '%/%'
      ORDER BY start_time DESC
    `, [`%${application}%`]);

    const result = await db.query(`
        SELECT name, status, order_date, start_time, end_time, application, folder
        FROM jobs
        WHERE application LIKE $1
        AND order_date >= CURRENT_DATE
      `, [`%${application}%`]);

    const jobsDB = result.rows;

    totalJobs[application] = {
      BSD: {
        switchOver: 0,
        rollback: 0
      },
      DCI: {
        switchOver: 0,
        rollback: 0
      }
    }
    totalJobsDone[application] = {
      BSD: {
        switchOver: 0,
        rollback: 0
      },
      DCI: {
        switchOver: 0,
        rollback: 0
      }
    }

    const filterJobsDB = (action, application, location) => {
      return jobsDB.filter(item => 
        item.folder.includes(`BDISOA_${action}_${application}_To_${location}`)
      ).length
    };

    totalJobs[application].DCI.switchOver = filterJobsDB('Switch_Over', application, 'BSD');
    totalJobs[application].DCI.rollback = filterJobsDB('Rollback', application, 'DCI');
    totalJobs[application].BSD.switchOver = filterJobsDB('Switch_Over', application, 'DCI');
    totalJobs[application].BSD.rollback = filterJobsDB('Rollback', application, 'BSD');

    const filterJobsDBDone = (action, application, location) => {
      return jobsDB.filter(item => 
        item.folder.includes(`BDISOA_${action}_${application}_To_${location}`) &&
        item.status === 'Ended OK'
      ).length
    };

    totalJobsDone[application].DCI.switchOver = filterJobsDBDone('Switch_Over', application, 'BSD');
    totalJobsDone[application].DCI.rollback = filterJobsDBDone('Rollback', application, 'DCI');
    totalJobsDone[application].BSD.switchOver = filterJobsDBDone('Switch_Over', application, 'DCI');
    totalJobsDone[application].BSD.rollback = filterJobsDBDone('Rollback', application, 'BSD');

    // convert timestamps to UTC ISO strings
    jobs.rows.forEach(row => {
      row.start_time = row.start_time ? new Date(row.start_time).toISOString() : null;
      row.end_time = row.end_time ? new Date(row.end_time).toISOString() : null;
    });

    folders.rows.forEach(row => {
      row.start_time = row.start_time ? new Date(row.start_time).toISOString() : null;
      row.end_time = row.end_time ? new Date(row.end_time).toISOString() : null;
      row.estimated_start_time = row.estimated_start_time ? new Date(row.estimated_start_time).toISOString() : null;
      row.estimated_end_time = row.estimated_end_time ? new Date(row.estimated_end_time).toISOString() : null;
    });

    result.rows.forEach(row => {
      row.start_time = row.start_time ? new Date(row.start_time).toISOString() : null;
      row.end_time = row.end_time ? new Date(row.end_time).toISOString() : null;
    });

    res.json({
      jobs: jobs.rows,
      folders: folders.rows,
      totalJobsRunbook: totalJobs,
      totalJobsDoneRunbook: totalJobsDone
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to fetch data jobs for application: ${application}` });
    console.log(error)
  }
});

app.get('/api/jobs-folders/export/:app', async (req, res) => {
  console.log('exporting csv');
  const application = req.params.app;
  const { type, runbook, status, date } = req.query;

  try {
    // Initialize dynamic conditions and parameters
    let jobConditions = ['application LIKE $1', "created_at >= DATE_TRUNC('month', CURRENT_DATE)"];
    let jobParams = [`%${application}%`];

    let folderConditions = ['application LIKE $1', "created_at >= DATE_TRUNC('month', CURRENT_DATE)"];
    let folderParams = [`%${application}%`];

    // Add dynamic filters for jobs
    if (type) {
      jobConditions.push('type = $' + (jobParams.length + 1));
      jobParams.push(type);
    }
    if (runbook) {
      jobConditions.push('folder LIKE $' + (jobParams.length + 1));
      jobParams.push(`%${runbook}%`);
      folderConditions.push('name LIKE $' + (folderParams.length + 1));
      folderParams.push(`%${runbook}%`);
    }
    if (status) {
      jobConditions.push('status LIKE $' + (jobParams.length + 1));
      jobParams.push(`%${status}%`);
      folderConditions.push('status LIKE $' + (folderParams.length + 1));
      folderParams.push(`%${status}%`);
    }
    if (date) {
      jobConditions.push('order_date = $' + (jobParams.length + 1));
      jobParams.push(date);
      folderConditions.push('order_date = $' + (folderParams.length + 1));
      folderParams.push(date);
    }

    // Construct SQL queries dynamically
    const jobsQuery = `
      SELECT folder, name, type, status,
        NULLIF(start_time, '1999-01-01 00:00:00') AS start_time,
        NULLIF(end_time, '1999-01-01 00:00:00') AS end_time,
        (CASE 
          WHEN start_time IS NOT NULL AND end_time IS NOT NULL THEN 
            end_time - start_time
          ELSE NULL
        END) AS duration,
        order_date, application, sub_application
      FROM jobs 
      WHERE ${jobConditions.join(' AND ')}
      ORDER BY start_time DESC NULLS LAST
    `;

    const foldersQuery = `
      SELECT name, application, status, order_date,
        NULLIF(start_time, '1999-01-01 00:00:00') AS start_time, 
        NULLIF(end_time, '1999-01-01 00:00:00') AS end_time, 
        (CASE 
          WHEN start_time IS NOT NULL AND end_time IS NOT NULL THEN 
            end_time - start_time
          ELSE NULL
        END) AS duration,
        NULLIF(estimated_start_time, '1999-01-01 00:00:00') AS estimated_start_time, 
        NULLIF(estimated_end_time, '1999-01-01 00:00:00') AS estimated_end_time
      FROM folders
      WHERE ${folderConditions.join(' AND ')}
      ORDER BY start_time DESC
    `;

    // Fetch data for jobs and folders
    const jobs = await db.query(jobsQuery, jobParams);
    const folders = await db.query(foldersQuery, folderParams);

    // Initialize a new workbook and add two sheets
    const workbook = new ExcelJS.Workbook();
    const jobsSheet = workbook.addWorksheet('Jobs');
    const foldersSheet = workbook.addWorksheet('Folders');

    // Define columns for the "Jobs" sheet
    jobsSheet.columns = [
      { header: 'Folder', key: 'folder' },
      { header: 'Name', key: 'name' },
      { header: 'Type', key: 'type' },
      { header: 'Status', key: 'status' },
      { header: 'Start Time', key: 'start_time' },
      { header: 'End Time', key: 'end_time' },
      { header: 'Duration', key: 'duration' },
      { header: 'Order Date', key: 'order_date' },
      { header: 'Application', key: 'application' },
      { header: 'Sub Application', key: 'sub_application' }
    ];

    console.log('check:', jobs.rows[0], jobs.rows[1], jobs.rows[2], jobs.rows[3])
    // Add job data to "Jobs" sheet
    jobs.rows.forEach(row => {
      row.start_time = row.start_time ? new Date(row.start_time).toLocaleString('en-GB') : null;
      row.end_time = row.end_time ? new Date(row.end_time).toLocaleString('en-GB') : null;
      row.duration = row.duration ? formatDuration(row.duration) : null;
      jobsSheet.addRow(row);
    });

    console.log('check:', jobs.rows[0], jobs.rows[1], jobs.rows[2], jobs.rows[3])

    // Define columns for the "Folders" sheet
    foldersSheet.columns = [
      { header: 'Name', key: 'name' },
      { header: 'Application', key: 'application' },
      { header: 'Status', key: 'status' },
      { header: 'Start Time', key: 'start_time' },
      { header: 'End Time', key: 'end_time' },
      { header: 'Estimated Start Time', key: 'estimated_start_time' },
      { header: 'Estimated End Time', key: 'estimated_end_time' }
    ];

    // Add folder data to "Folders" sheet
    folders.rows.forEach(row => {
      row.start_time = row.start_time ? new Date(row.start_time).toLocaleString('en-GB') : null;
      row.end_time = row.end_time ? new Date(row.end_time).toLocaleString('en-GB') : null; 
      row.duration = row.duration ? formatDuration(row.duration) : null;
      row.estimated_start_time = row.estimated_start_time ? new Date(row.estimated_start_time).toLocaleString('en-GB') : null;
      row.estimated_end_time = row.estimated_end_time ? new Date(row.estimated_end_time).toLocaleString('en-GB') : null;
      foldersSheet.addRow(row);
    });

    // Set response headers and send workbook
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=jobs_folders.xlsx');

    await workbook.xlsx.write(res);
    console.log('export ok');
    res.end();
  } catch (error) {
    res.status(500).json({ error: `Failed to export data for application: ${application}` });
    console.error(error);
  }
});

app.get('/api/current-active-and-readiness', async (req, res) => {
  try {
    const currentActive = await db.query(`
      SELECT name, status, MAX(start_time) as start_time
      FROM jobs
      WHERE (
        name LIKE '%APP_CHK_%'
      )
      GROUP BY name, status
    `);
    const readiness = await db.query(`
      SELECT  name, status, MAX(start_time) as start_time
      FROM folders
      WHERE (
        ${appList.map(item => 
          `name LIKE '%BDISOA_Readiness_${item}_%'`
        ).join(' OR ')}
      )
      AND name NOT LIKE '%/%'
      GROUP BY name, status
    `);
    const preimplement = await db.query(`
      SELECT  name, status, MAX(start_time) as start_time
      FROM folders
      WHERE (
        ${appList.map(item => 
          `name LIKE '%BDISOA_PreImplement_${item}_%'`
        ).join(' OR ')}
      )
      AND name NOT LIKE '%/%'
      GROUP BY name, status
    `);

    res.status(200).json({
      currentActive: currentActive.rows,
      readiness: readiness.rows,
      preImplement: preimplement.rows
    })
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error', message: error.message })
  }

});

app.get('/api/check-readiness', async (req, res) => {
  try {
    const results = await db.query(`
      SELECT name, application, status, MAX(start_time) as start_time, 
        CASE
          WHEN name LIKE '%BDISOA_Readiness%' THEN 'readiness'
          WHEN name LIKE '%BDISOA_PreImplement%' THEN 'preimplement'
        END as type
      FROM folders
      WHERE (name LIKE '%BDISOA_Readiness%' OR name LIKE '%BDISOA_PreImplement%')
      AND name NOT LIKE '%/%'
      GROUP BY name, application, status
    `);

    const readiness = results.rows.filter(row => row.type === 'readiness');
    const preimplement = results.rows.filter(row => row.type === 'preimplement');

    res.json({
      readiness,
      preimplement
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: `Failed to fetch data readiness: ${error}` })
  }
});

app.get('/api/current-active', async (req, res) => {
  try {
    const checkReadiness = await db.query(`
      SELECT 
        folder,
        name,
        status,
        application,
        start_time
      FROM (
        SELECT 
          folder,
          name,
          status,
          application,
          start_time,
          ROW_NUMBER() OVER (PARTITION BY application, name ORDER BY start_time DESC) AS rn
        FROM jobs 
        WHERE
          (name = 'Job Check DCI Active' OR name = 'Job Check BSD Active') 
          AND start_time >= CURRENT_DATE
      ) AS ranked_jobs
      WHERE rn = 1;
    `);
    const checkPreimplement = await db.query(`
      SELECT 
        name, 
        application, 
        status, 
        MAX(start_time) AS start_time
      FROM folders
      WHERE 
        (name = 'BDISOA_PreImplement_GBPM_To_BSD' OR name = 'BDISOA_PreImplement_GBPM_To_DCI')
        AND start_time >= CURRENT_DATE
      GROUP BY name, application, status
      ORDER BY start_time DESC
    `);
    res.json({ 
      checkReadiness: checkReadiness.rows, 
      checkPreimplement: checkPreimplement.rows 
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Failed to fetch data current active' })
  }
});

startTaskUpdateAllData();

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`)
});