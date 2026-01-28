const ZktecoJs = require('zkteco-js');
const { spawn } = require('child_process');

// Start the mock device server in background
console.log('Starting mock ZKTeco device server...');
const serverProcess = spawn('node', ['zkfixed.js'], {
  stdio: 'pipe'
});

serverProcess.stdout.on('data', (data) => {
  console.log(`Server: ${data}`);
});

// Wait a moment for server to start
setTimeout(async () => {
  try {
    console.log('Creating device instance...');
    const device = new ZktecoJs('127.0.0.1', 4371, 5000);
    
    console.log('Connecting to device...');
    await device.createSocket();
    console.log('Connected successfully');
    
    // Test ORIGINAL methods as requested
    console.log('\n=== TESTING ORIGINAL METHODS ===');
    
    console.log('Getting users...');
    const users = await device.getUsers();
    console.log('✅ users result:', users.data.length, 'users found');
    
    console.log('Getting attendances...');
    const attendances = await device.getAttendances();
    console.log('✅ attendances result:', attendances.data.length, 'records found');
    
    if (users.data.length > 0) {
      console.log('Sample user:', users.data[0]);
    }
    
    if (attendances.data.length > 0) {
      console.log('Sample attendance:', attendances.data[0]);
    }
    
    await device.disconnect();
    console.log('Disconnected successfully');
    
  } catch (error) {
    console.error('Error:', error);
    if (error.message) console.error('Message:', error.message);
    if (error.stack) console.error('Stack:', error.stack);
  } finally {
    // Clean up
    // serverProcess.kill();
    // process.exit(0);
  }
}, 2000);