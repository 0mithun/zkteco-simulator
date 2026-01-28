const net = require('net');
const COMMANDS = {
  CMD_CONNECT: 1000,
  CMD_EXIT: 1001,
  CMD_ENABLEDEVICE: 1002,
  CMD_DISABLEDEVICE: 1003,
  CMD_RESTART: 1004,
  CMD_POWEROFF: 1005,
  CMD_SLEEP: 1006,
  CMD_RESUME: 1007,
  CMD_CAPTUREFINGER: 1009,
  CMD_TEST_TEMP: 1011,
  CMD_CAPTUREIMAGE: 1012,
  CMD_REFRESHDATA: 1013,
  CMD_REFRESHOPTION: 1014,
  CMD_TESTVOICE: 1017,
  CMD_GET_VERSION: 1100,
  CMD_CHANGE_SPEED: 1101,
  CMD_AUTH: 1102,
  CMD_PREPARE_DATA: 1500,
  CMD_DATA: 1501,
  CMD_FREE_DATA: 1502,
  CMD_DATA_WRRQ: 1503,
  CMD_DATA_RDY: 1504,
  CMD_DB_RRQ: 7,
  CMD_USER_WRQ: 8,
  CMD_USERTEMP_RRQ: 9,
  CMD_USERTEMP_WRQ: 10,
  CMD_OPTIONS_RRQ: 11,
  CMD_OPTIONS_WRQ: 12,
  CMD_ATTLOG_RRQ: 13,
  CMD_CLEAR_DATA: 14,
  CMD_CLEAR_ATTLOG: 15,
  CMD_DELETE_USER: 18,
  CMD_DELETE_USERTEMP: 19,
  CMD_CLEAR_ADMIN: 20,
  CMD_USERGRP_RRQ: 21,
  CMD_USERGRP_WRQ: 22,
  CMD_USERTZ_RRQ: 23,
  CMD_USERTZ_WRQ: 24,
  CMD_GRPTZ_RRQ: 25,
  CMD_GRPTZ_WRQ: 26,
  CMD_TZ_RRQ: 27,
  CMD_TZ_WRQ: 28,
  CMD_ULG_RRQ: 29,
  CMD_ULG_WRQ: 30,
  CMD_UNLOCK: 31,
  CMD_CLEAR_ACC: 32,
  CMD_CLEAR_OPLOG: 33,
  CMD_OPLOG_RRQ: 34,
  CMD_GET_FREE_SIZES: 50,
  CMD_ENABLE_CLOCK: 57,
  CMD_STARTVERIFY: 60,
  CMD_STARTENROLL: 61,
  CMD_CANCELCAPTURE: 62,
  CMD_STATE_RRQ: 64,
  CMD_WRITE_LCD: 66,
  CMD_CLEAR_LCD: 67,
  CMD_GET_PINWIDTH: 69,
  CMD_SMS_WRQ: 70,
  CMD_SMS_RRQ: 71,
  CMD_DELETE_SMS: 72,
  CMD_UDATA_WRQ: 73,
  CMD_DELETE_UDATA: 74,
  CMD_DOORSTATE_RRQ: 75,
  CMD_WRITE_MIFARE: 76,
  CMD_EMPTY_MIFARE: 78,
  CMD_VERIFY_WRQ: 79,
  CMD_VERIFY_RRQ: 80,
  CMD_TMP_WRITE: 87,
  CMD_CHECKSUM_BUFFER: 119,
  CMD_DEL_FPTMP: 134,
  CMD_GET_TIME: 201,
  CMD_SET_TIME: 202,
  CMD_REG_EVENT: 500,
  CMD_ACK_OK: 2000,
  CMD_ACK_ERROR: 2001,
  CMD_ACK_DATA: 2002,
  CMD_ACK_RETRY: 2003,
  CMD_ACK_REPEAT: 2004,
  CMD_ACK_UNAUTH: 2005,
  CMD_ACK_UNKNOWN: 65535,
  CMD_ACK_ERROR_CMD: 65533,
  CMD_ACK_ERROR_INIT: 65532,
  CMD_ACK_ERROR_DATA: 65531,
  EF_ATTLOG: 1,
  EF_FINGER: 2,
  EF_ENROLLUSER: 4,
  EF_ENROLLFINGER: 8,
  EF_BUTTON: 16,
  EF_UNLOCK: 32,
  EF_VERIFY: 128,
  EF_FPFTR: 256,
  EF_ALARM: 512
}

const PORT = 4371;

// Mock data store
const users = new Map();
const attendances = [];
let attendanceId = 1;

// Initialize with some default data
users.set(1, {
  uid: 1,
  role: 0,
  password: '123456',
  name: 'John Doe',
  cardno: 0,
  userId: '1'
});

// Helper constants for protocol matching
const REQUEST_DATA = {
  GET_USERS: Buffer.from([0x01, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
  GET_ATTENDANCE_LOGS: Buffer.from([0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
};

const MAX_CHUNK = 65472;
const DATA_TRANSFERS = new Map();

// --- Existing functions (unchanged) ---
function calcChecksum(buf) {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) {
    sum += buf.readUInt16LE(i);
    sum = (sum & 0xffff) + (sum >> 16);
  }
  if (buf.length % 2 === 1) {
    sum += buf[buf.length - 1];
  }
  return (~sum) & 0xffff;
}

function createResponsePacket(command, sessionId, replyId, data = Buffer.alloc(0)) {
  const header = Buffer.alloc(8);
  header.writeUInt16LE(command, 0);
  header.writeUInt16LE(0, 2);
  header.writeUInt16LE(sessionId, 4);
  header.writeUInt16LE(replyId, 6);

  const packet = Buffer.concat([header, data]);
  const checksum = calcChecksum(packet);
  packet.writeUInt16LE(checksum, 2);

  return packet;
}

function buildTcpPacket(zkPacket) {
  const tcpHeader = Buffer.alloc(8);
  tcpHeader.writeUInt16LE(0x5050, 0);
  tcpHeader.writeUInt16LE(0x827d, 2);
  tcpHeader.writeUInt32LE(zkPacket.length, 4);
  return Buffer.concat([tcpHeader, zkPacket]);
}

function createUserData(uid, userid, name, password, role = 0, cardno = 0) {
  const userData = Buffer.alloc(72);
  userData.writeUInt16LE(uid, 0);
  userData.writeUInt16LE(role, 2);
  userData.writeUInt8(0, 4);
  userData.writeUInt8(0, 5);
  userData.writeUInt16LE(0, 6);

  userData.write(password.padEnd(8, '\0'), 3, 8, 'ascii');
  userData.write(name.padEnd(24, '\0'), 11, 24, 'ascii');
  userData.writeUInt32LE(cardno, 35);
  userData.writeUInt32LE(0, 40);
  userData.write(userid.padEnd(9, '\0'), 48, 9, 'ascii');

  return userData;
}

function createAttendanceRecord(userSn, userId) {
  const record = Buffer.alloc(40);
  record.writeUInt16LE(userSn, 0);
  record.write(userId.padEnd(9, '\0'), 2, 9, 'ascii');
  record.writeUInt16LE(0, 11);

  const timestamp = Math.floor(Date.now() / 1000);
  record.writeUInt32LE(timestamp, 27);
  record.writeUInt8(1, 26);
  record.writeUInt8(1, 31);
  record.fill(0, 32);

  return record;
}

// --- NEW PROTOCOL FUNCTIONS ---
function buffersEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function createDataTransfer(sessionId, data, replyId) {
  const transferKey = `${sessionId}`;
  DATA_TRANSFERS.set(transferKey, {
    data: data,
    offset: 0,
    totalSize: data.length,
    replyId: replyId,
    chunks: Math.ceil(data.length / MAX_CHUNK)
  });
  console.log(`Created data transfer for session ${sessionId}, size: ${data.length}, chunks: ${Math.ceil(data.length / MAX_CHUNK)}`);
}

function sendDataChunk(socket, sessionId) {
  const transferKey = `${sessionId}`;
  const transfer = DATA_TRANSFERS.get(transferKey);

  if (!transfer) {
    console.log(`No transfer found for session ${sessionId}`);
    return false;
  }

  if (transfer.offset >= transfer.totalSize) {
    console.log(`Transfer complete for session ${sessionId}`);
    DATA_TRANSFERS.delete(transferKey);
    return false;
  }

  const chunkSize = Math.min(MAX_CHUNK, transfer.totalSize - transfer.offset);
  const chunk = transfer.data.slice(transfer.offset, transfer.offset + chunkSize);
  transfer.offset += chunkSize;

  const packet = createResponsePacket(COMMANDS.CMD_DATA, sessionId, transfer.replyId, chunk);
  socket.write(buildTcpPacket(packet));

  console.log(`Sent chunk ${transfer.offset}/${transfer.totalSize} for session ${sessionId}`);
  return true;
}


function handleZktecoDataRequest(data, sessionId, replyId, socket) {
  // Handle GET_USERS request
  if (buffersEqual(data, REQUEST_DATA.GET_USERS)) {
    console.log('Processing GET_USERS request');

    // Create user data with count
    const userCount = users.size;
    const allUserData = Buffer.alloc(4 + (userCount * 72));
    allUserData.writeUInt32LE(userCount, 0);

    let offset = 4;
    for (const [uid, user] of users) {
      const userData = createUserData(user.uid, user.userId, user.name, user.password, user.role, user.cardno);
      userData.copy(allUserData, offset);
      offset += 72;
    }

    // PREPARE_DATA with size and remaining packets
    const prepareData = Buffer.alloc(8);
    prepareData.writeUInt32LE(allUserData.length, 0);
    prepareData.writeUInt32LE(1, 4); // 1 remaining packet

    const prepareResponse = createResponsePacket(COMMANDS.CMD_PREPARE_DATA, sessionId, replyId, prepareData);
    const tcpPacket = buildTcpPacket(prepareResponse);
    console.log('Sending PREPARE_DATA - hex:', tcpPacket.toString('hex').substring(0, 64));
    socket.write(tcpPacket);

    //立即发送数据 (send data immediately)
    const dataResponse = createResponsePacket(COMMANDS.CMD_DATA, sessionId, replyId, allUserData);
    const dataTcpPacket = buildTcpPacket(dataResponse);
    console.log('Sending DATA - hex:', dataTcpPacket.toString('hex').substring(0, 64));
    socket.write(dataTcpPacket);

    return true;
  }

  // Handle GET_ATTENDANCE_LOGS request
  if (buffersEqual(data, REQUEST_DATA.GET_ATTENDANCE_LOGS)) {
    console.log('Processing GET_ATTENDANCE_LOGS request');

    // Create attendance data with count
    const attendanceCount = attendances.length;
    const allAttendanceData = Buffer.alloc(4 + (attendanceCount * 40));
    allAttendanceData.writeUInt32LE(attendanceCount, 0);

    let offset = 4;
    for (const attendance of attendances) {
      const record = createAttendanceRecord(attendance.sn, attendance.userId);
      record.copy(allAttendanceData, offset);
      offset += 40;
    }

    // PREPARE_DATA with size and remaining packets
    const prepareData = Buffer.alloc(8);
    prepareData.writeUInt32LE(allAttendanceData.length, 0);
    prepareData.writeUInt32LE(1, 4); // 1 remaining packet

    const prepareResponse = createResponsePacket(COMMANDS.CMD_PREPARE_DATA, sessionId, replyId, prepareData);
    socket.write(buildTcpPacket(prepareResponse));

    //立即发送数据 (send data immediately)
    const dataResponse = createResponsePacket(COMMANDS.CMD_DATA, sessionId, replyId, allAttendanceData);
    socket.write(buildTcpPacket(dataResponse));

    return true;
  }

  return false;
}

function handleDataReady(sessionId, replyId, data, socket) {
  // Parse chunk request parameters
  let start = 0, size = 0;
  if (data && data.length >= 8) {
    start = data.readUInt32LE(0);
    size = data.readUInt32LE(4);
  }

  // Send next chunk or complete
  const hasMoreData = sendDataChunkRange(socket, sessionId, start, size);

  if (!hasMoreData) {
    // Transfer complete, send ACK_OK
    const ackResponse = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId);
    socket.write(buildTcpPacket(ackResponse));
  }
}

function sendDataChunkRange(socket, sessionId, start, size) {
  const transferKey = `${sessionId}`;
  const transfer = DATA_TRANSFERS.get(transferKey);

  if (!transfer) {
    console.log(`No transfer found for session ${sessionId}`);
    return false;
  }

  // Send the requested chunk range
  const chunkSize = Math.min(size, transfer.totalSize - start);
  if (chunkSize <= 0) {
    console.log(`Transfer complete for session ${sessionId}`);
    DATA_TRANSFERS.delete(transferKey);
    return false;
  }

  const chunk = transfer.data.slice(start, start + chunkSize);
  const packet = createResponsePacket(COMMANDS.CMD_DATA, sessionId, transfer.replyId, chunk);
  socket.write(buildTcpPacket(packet));

  console.log(`Sent chunk ${start}-${start + chunkSize}/${transfer.totalSize} for session ${sessionId}`);
  
  // Check if we've sent all data
  if (start + chunkSize >= transfer.totalSize) {
    console.log(`Transfer complete for session ${sessionId}`);
    DATA_TRANSFERS.delete(transferKey);
    return false;
  }

  return true;
}

// --- SERVER IMPLEMENTATION (unchanged except for new cases) ---
const server = net.createServer(socket => {
  console.log('New connection from:', socket.remoteAddress, socket.remotePort);

  socket.on('data', (chunk) => {
    try {
      let packet = null;

      if (chunk.length >= 8) {
        const magic = chunk.readUInt16LE(0);
        if (magic === 0x5050) {
          const packetLength = chunk.readUInt32LE(4);
          if (chunk.length >= 8 + packetLength) {
            packet = chunk.slice(8, 8 + packetLength);
          }
        }
      }

      if (!packet && chunk.length >= 8) {
        packet = chunk;
      }

      if (!packet || packet.length < 8) return;

      const command = packet.readUInt16LE(0);
      const sessionId = packet.readUInt16LE(4);
      const replyId = packet.readUInt16LE(6);
      const data = packet.slice(8);

      console.log(`CMD: ${command} | Session: ${sessionId} | Reply: ${replyId}`);

      switch (command) {
        case COMMANDS.CMD_CONNECT: {
          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId);
          socket.write(buildTcpPacket(response));
          break;
        }

        case COMMANDS.CMD_OPTIONS_RRQ: {
          const key = data.toString('ascii').replace(/\0/g, '');
          let value = '';

          switch (key) {
            case '~OEMVendor': value = 'ZKTeco'; break;
            case '~ProductTime': value = '2009-12-21T15:00:58.000Z'; break;
            case 'MAC': value = '00:1A:2B:3C:4D:5E'; break;
            case '~SerialNumber': value = 'K401234567'; break;
            case '~ZKFPVersion': value = '10.0.1'; break;
            case '~DeviceName': value = 'ZKTeco K40'; break;
            case '~Platform': value = 'K40'; break;
            case '~OS': value = 'Linux 4.9'; break;
            case 'WorkCode': value = '0'; break;
            case '~PIN2Width': value = '4'; break;
            case 'FaceFunOn': value = '0'; break;
            case '~SSR': value = '0'; break;
            default: value = 'Unknown'; break;
          }

          const payload = Buffer.from(`${key}=${value}\0`, 'ascii');
          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId, payload);
          socket.write(buildTcpPacket(response));
          break;
        }

        case COMMANDS.CMD_DB_RRQ: {
          const allUserData = Buffer.alloc(4 + (users.size * 72));
          allUserData.writeUInt32LE(users.size, 0);

          let offset = 4;
          for (const [uid, user] of users) {
            const userData = createUserData(user.uid, user.userId, user.name, user.password, user.role, user.cardno);
            userData.copy(allUserData, offset);
            offset += 72;
          }

          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId, allUserData);
          socket.write(buildTcpPacket(response));
          break;
        }

        case COMMANDS.CMD_ATTLOG_RRQ: {
          const allAttendanceData = Buffer.alloc(4 + (attendances.length * 40));
          allAttendanceData.writeUInt32LE(attendances.length, 0);

          let offset = 4;
          for (const attendance of attendances) {
            const record = createAttendanceRecord(attendance.sn, attendance.userId);
            record.copy(allAttendanceData, offset);
            offset += 40;
          }

          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId, allAttendanceData);
          socket.write(buildTcpPacket(response));
          break;
        }

        case COMMANDS.CMD_GET_FREE_SIZES: {
          // console.log('users count: ', users.size)
          // console.log('attendances count: ', attendances.length)
          // console.log('logCapacity: ', 50000)
          // const sizeData = Buffer.alloc(76);
          // sizeData.writeUInt32LE(users.size, 24);
          // sizeData.writeUInt32LE(attendances.length, 40);
          // sizeData.writeUInt32LE(50000, 72);
          // const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId, sizeData);
          // socket.write(buildTcpPacket(response));
          // break;

          const sizeData = Buffer.alloc(76, 0);

  sizeData.writeUInt32LE(users.size, 8);       // dwUserCount
  sizeData.writeUInt32LE(attendances.length, 24); // dwAttLogCount
  sizeData.writeUInt32LE(50000, 56);           // dwLogCapacity

  const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId, sizeData);
  socket.write(buildTcpPacket(response));
  break;
        }

        case COMMANDS.CMD_GET_TIME: {
          const timeData = Buffer.alloc(12);
          const now = new Date();
          timeData.writeUInt8(now.getFullYear() - 2000, 0);
          timeData.writeUInt8(now.getMonth() + 1, 1);
          timeData.writeUInt8(now.getDate(), 2);
          timeData.writeUInt8(now.getHours(), 3);
          timeData.writeUInt8(now.getMinutes(), 4);
          timeData.writeUInt8(now.getSeconds(), 5);
          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId, timeData);
          socket.write(buildTcpPacket(response));
          break;
        }

        case COMMANDS.CMD_USER_WRQ: {
          if (data.length >= 72) {
            const uid = data.readUInt16LE(0);
            const userId = data.toString('ascii', 48, 57).replace(/\0/g, '');
            const name = data.toString('ascii', 11, 35).replace(/\0/g, '');
            const password = data.toString('ascii', 3, 11).replace(/\0/g, '');
            const role = data.readUInt16LE(2);
            const cardno = data.readUInt32LE(35);

            users.set(uid, { uid, userId, name, password, role, cardno });
            console.log(`User added/updated: UID=${uid}, UserID=${userId}, Name=${name}`);
          }

          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId);
          socket.write(buildTcpPacket(response));
          break;
        }

        case COMMANDS.CMD_DELETE_USER: {
          if (data.length >= 2) {
            const uid = data.readUInt16LE(0);
            users.delete(uid);
            console.log(`User deleted: UID=${uid}`);
          }

          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId);
          socket.write(buildTcpPacket(response));
          break;
        }

        case COMMANDS.CMD_CLEAR_ATTLOG: {
          attendances.length = 0;
          attendanceId = 1;
          console.log('Attendance logs cleared');

          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId);
          socket.write(buildTcpPacket(response));
          break;
        }

        case COMMANDS.CMD_CLEAR_DATA: {
          users.clear();
          attendances.length = 0;
          attendanceId = 1;

          users.set(1, {
            uid: 1,
            role: 0,
            password: '123456',
            name: 'John Doe',
            cardno: 0,
            userId: '1'
          });

          console.log('All data cleared');

          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId);
          socket.write(buildTcpPacket(response));
          break;
        }

        // --- NEW PROTOCOL HANDLING ---
        case COMMANDS.CMD_FREE_DATA: {
          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId);
          socket.write(buildTcpPacket(response));
          break;
        }

        case COMMANDS.CMD_DATA_WRRQ: {
          // Handle GET_USERS request using simple direct response
          if (buffersEqual(data, REQUEST_DATA.GET_USERS)) {
            console.log('GET_USERS: Simple direct response');

            const userCount = users.size;
            const allUserData = Buffer.alloc(4 + (userCount * 72));
            allUserData.writeUInt32LE(userCount, 0);

            let offset = 4;
            for (const [uid, user] of users) {
              const userData = createUserData(user.uid, user.userId, user.name, user.password, user.role, user.cardno);
              userData.copy(allUserData, offset);
              offset += 72;
            }

            const response = createResponsePacket(COMMANDS.CMD_DATA, sessionId, replyId, allUserData);
            socket.write(buildTcpPacket(response));
            break;
          }

          // Handle GET_ATTENDANCE_LOGS request using simple direct response
          if (buffersEqual(data, REQUEST_DATA.GET_ATTENDANCE_LOGS)) {
            console.log('GET_ATTENDANCE_LOGS: Simple direct response');

            const attendanceCount = attendances.length;
            const allAttendanceData = Buffer.alloc(4 + (attendanceCount * 40));
            allAttendanceData.writeUInt32LE(attendanceCount, 0);

            let offset = 4;
            for (const attendance of attendances) {
              const record = createAttendanceRecord(attendance.sn, attendance.userId);
              record.copy(allAttendanceData, offset);
              offset += 40;
            }

            const response = createResponsePacket(COMMANDS.CMD_DATA, sessionId, replyId, allAttendanceData);
            socket.write(buildTcpPacket(response));
            break;
          }

          // Fall through to default handler
          const handled = handleZktecoDataRequest(data, sessionId, replyId, socket);
          if (!handled) {
            const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId);
            socket.write(buildTcpPacket(response));
          }
          break;
        }

        case COMMANDS.CMD_DATA_RDY: {
          handleDataReady(sessionId, replyId, data, socket);
          break;
        }

        default: {
          console.log(`Command ${command} acknowledged`);
          const response = createResponsePacket(COMMANDS.CMD_ACK_OK, sessionId, replyId);
          socket.write(buildTcpPacket(response));
          break;
        }
      }
    } catch (error) {
      console.error('Error processing command:', error);
    }
  });

  socket.on('close', () => {
    console.log('Connection closed:', socket.remoteAddress, socket.remotePort);
  });

  socket.on('error', err => {
    console.error('Socket error:', err.message);
  });
});

// Initialize sample data
users.set(1, { uid: 1, role: 0, password: '123456', name: 'John Doe', cardno: 0, userId: '1' });
users.set(2, { uid: 2, role: 0, password: '123456', name: 'Alex Jones', cardno: 0, userId: '2' });
users.set(3, { uid: 3, role: 1, password: '123456', name: 'Kura thai', cardno: 0, userId: '3' });
users.set(4, { uid: 4, role: 0, password: '123456', name: 'Robert william', cardno: 0, userId: '4' });
users.set(5, { uid: 5, role: 0, password: '123456', name: 'Nick james', cardno: 0, userId: '5' });
attendances.push({ sn: 1, userId: '1' });
attendances.push({ sn: 2, userId: '1' });

server.listen(PORT, () => {
  console.log(`Mock ZKTeco server running on port ${PORT}`);
  console.log(`Users: ${users.size}, Attendance records: ${attendances.length}`);
});