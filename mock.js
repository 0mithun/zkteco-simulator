const net = require('net');

const PORT = 4371;

// Client CMD constants
const CMD = {
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
  CMD_ACK_ERROR_DATA: 65531
};

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
function buildTcpPacket(zkPacket) {
  const tcpHeader = Buffer.alloc(4);
  tcpHeader.writeUInt16LE(0x5050, 0);           // magic
  tcpHeader.writeUInt16LE(zkPacket.length, 2);  // ZK payload length
  return Buffer.concat([tcpHeader, zkPacket]);
}

function createZkPacket(command, sessionId, replyId, data = Buffer.alloc(0)) {
  const header = Buffer.alloc(12);
  header.writeUInt16LE(0, 0);      // tcpSeq
  header.writeUInt16LE(0, 2);      // tcpFlags
  header.writeUInt16LE(command, 4);
  header.writeUInt16LE(0, 6);      // checksum placeholder
  header.writeUInt16LE(sessionId, 8);
  header.writeUInt16LE(replyId, 10);

  const packet = Buffer.concat([header, data]);

  const checksum = calcChecksum(packet);
  packet.writeUInt16LE(checksum, 6);

  return packet;
}





function createResponsePacket(command, sessionId, replyId, data = Buffer.alloc(0)) {
  const header = Buffer.alloc(8);
  header.writeUInt16LE(command, 0);
  header.writeUInt16LE(0, 2); // checksum placeholder
  header.writeUInt16LE(sessionId, 4);
  header.writeUInt16LE(replyId, 6);

  const packet = Buffer.concat([header, data]);
  const checksum = calcChecksum(packet);
  packet.writeUInt16LE(checksum, 2);

  return packet;
}

function createUserRecord(uid = 1, name = "John Doe", password = "123456") {
  const userData = Buffer.alloc(72);
  userData.writeUInt16LE(uid, 0);        // UID
  userData.writeUInt16LE(0, 2);          // Privilege
  userData.writeUInt8(0, 4);             // Password flag
  userData.writeUInt8(0, 5);             // Reserved
  userData.writeUInt16LE(0, 6);          // Group ID
  userData.write(name + '\0', 8, 24);    // Name
  userData.write(password + '\0', 32, 8); // Password
  userData.fill(0, 40);                  // Card number
  userData.fill(0, 48);                 // Reserved
  return userData;
}

function createAttendanceLog(uid = 1, recordTime = null) {
  const logData = Buffer.alloc(16);
  logData.writeUInt16LE(uid, 0);               // User ID
  logData.writeUInt8(1, 2);                    // Device ID
  logData.writeUInt8(0, 3);                    // Reserved
  logData.writeUInt32LE(recordTime || Math.floor(Date.now() / 1000), 4); // Timestamp
  logData.writeUInt8(1, 8);                    // Verify type
  logData.writeUInt8(0, 9);                    // Reserved
  logData.writeUInt16LE(0, 10);                // Work code
  logData.fill(0, 12);                         // Reserved
  return logData;
}

// Server
const server = net.createServer(socket => {
  console.log('New connection:', socket.remoteAddress, socket.remotePort);

  socket.on('data', (chunk) => {
    let packet = null;
    
    // Try to parse with TCP header (format: magic(2) + reserved(2) + length(2) + reserved(2))
    if (chunk.length >= 8) {
      const magic = chunk.readUInt16LE(0);
      if (magic === 0x5050) {
        const packetLength = chunk.readUInt16LE(4);
        if (chunk.length >= 8 + packetLength) {
          packet = chunk.slice(8, 8 + packetLength);
        }
      }
    }
    
    // Fallback to direct parsing
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
      case 1000: { // CMD_CONNECT
        const response = createResponsePacket(2000, sessionId, replyId);
        // Send raw response without TCP header
        socket.write(response);
        break;
      }

      case 11: { // CMD_OPTIONS_RRQ
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
        const response = createResponsePacket(2000, sessionId, replyId, payload);
        // Send raw response without TCP header
        socket.write(response);
        break;
      }



      // --- GET USERS (CMD 7) ---
      case 7: { 
        const userData = createUserRecord(1, "John Doe", "123456");
        
        // Step 1: Send Size as ACK_OK (2000) with 4-byte payload
        // zkteco-js expects exactly 4 bytes for the total size here
        const sizeBuf = Buffer.alloc(4);
        sizeBuf.writeUInt32LE(userData.length, 0);
        socket.write(buildTcpPacket(createZkPacket(2000, sessionId, replyId, sizeBuf)));

        // Step 2: Send actual data (1501) after a short delay
        setTimeout(() => {
          socket.write(buildTcpPacket(createZkPacket(1501, sessionId, replyId, userData)));

          // Step 3: Send final ACK_OK (2000) with empty payload to end the loop
          setTimeout(() => {
            socket.write(buildTcpPacket(createZkPacket(2000, sessionId, replyId)));
          }, 100);
        }, 100);
        break;
      }

      // --- GET ATTENDANCE (CMD 13) ---
      case 13: { 
        const logData = createAttendanceLog(1);
        
        const sizeBuf = Buffer.alloc(4);
        sizeBuf.writeUInt32LE(logData.length, 0);
        socket.write(buildTcpPacket(createZkPacket(2000, sessionId, replyId, sizeBuf)));

        setTimeout(() => {
          socket.write(buildTcpPacket(createZkPacket(1501, sessionId, replyId, logData)));
          setTimeout(() => {
            socket.write(buildTcpPacket(createZkPacket(2000, sessionId, replyId)));
          }, 100);
        }, 100);
        break;
      }

      // --- ATTENDANCE SIZE (CMD 64 or 50) ---
      case 64: { // CMD_STATE_RRQ
        const sizeData = Buffer.alloc(4);
        sizeData.writeUInt32LE(1, 0); // Mocking 1 record
        socket.write(buildTcpPacket(createZkPacket(2000, sessionId, replyId, sizeData)));
        break;
      }

      // --- SET/DELETE/CLEAR HANDLERS ---
      case 8:    // CMD_USER_WRQ
      case 18:   // CMD_DELETE_USER
      case 14:   // CMD_CLEAR_DATA
      case 15:   // CMD_CLEAR_ATTLOG
      case 134:  // CMD_DEL_FPTMP
      case 1013: // CMD_REFRESHDATA
      case 1503: // CMD_DATA_WRRQ
        socket.write(buildTcpPacket(createZkPacket(2000, sessionId, replyId)));
        break;



      case 50: { // CMD_GET_FREE_SIZES
        const sizeData = Buffer.alloc(76);
        sizeData.writeUInt32LE(10, 24);  // User count
        sizeData.writeUInt32LE(100, 40); // Log count  
        sizeData.writeUInt32LE(50000, 72); // Log capacity
        const response = createResponsePacket(2000, sessionId, replyId, sizeData);
        socket.write(response);
        break;
      }

      case 201: { // CMD_GET_TIME
        const timeData = Buffer.alloc(12);
        const now = new Date();
        timeData.writeUInt8(now.getFullYear() - 2000, 0);
        timeData.writeUInt8(now.getMonth() + 1, 1);
        timeData.writeUInt8(now.getDate(), 2);
        timeData.writeUInt8(now.getHours(), 3);
        timeData.writeUInt8(now.getMinutes(), 4);
        timeData.writeUInt8(now.getSeconds(), 5);
        const response = createResponsePacket(2000, sessionId, replyId, timeData);
        socket.write(response);
        break;
      }

      case 8:   // CMD_USER_WRQ
      case 18:  // CMD_DELETE_USER
      case 14:  // CMD_CLEAR_DATA
      case 15:  // CMD_CLEAR_ATTLOG
      case 134: // CMD_DEL_FPTMP
      case 32:  // CMD_CLEAR_ACC
      case 33:  // CMD_CLEAR_OPLOG
      case 1002: // CMD_ENABLEDEVICE
      case 1003: // CMD_DISABLEDEVICE
      case 1502: // CMD_FREE_DATA
      case 202:  // CMD_SET_TIME
      case 62:   // CMD_CANCELCAPTURE
      case 67:   // CMD_CLEAR_LCD
      case 66:   // CMD_WRITE_LCD
      case 31:   // CMD_UNLOCK
      case 57:   // CMD_ENABLE_CLOCK
      case 64:   // CMD_STATE_RRQ
      case 69:   // CMD_GET_PINWIDTH
      case 1100: // CMD_GET_VERSION
        const ackResponse = createResponsePacket(2000, sessionId, replyId);
        const tcpAckResponse = Buffer.concat([
          Buffer.from([0x50, 0x50]),
          Buffer.from([ackResponse.length & 0xff, (ackResponse.length >> 8) & 0xff]),
          ackResponse
        ]);
        socket.write(tcpAckResponse);
        break;

      default: {
        console.log(`Unhandled command: ${command}`);
        const defaultResponse = createResponsePacket(2000, sessionId, replyId);
        const tcpDefaultResponse = Buffer.concat([
          Buffer.from([0x50, 0x50]),
          Buffer.from([defaultResponse.length & 0xff, (defaultResponse.length >> 8) & 0xff]),
          defaultResponse
        ]);
        socket.write(tcpDefaultResponse);
        break;
      }
    }
  });

  socket.on('close', () => console.log('Connection closed:', socket.remoteAddress, socket.remotePort));
  socket.on('error', err => console.log('Socket error:', err.message));
});

server.listen(PORT, () => console.log(`Mock ZKTeco server running on port ${PORT}`));