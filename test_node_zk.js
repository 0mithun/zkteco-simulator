// const ZktecoJs = require('zkteco-js');
const ZktecoJs = require('node-zklib');

async function testAllCommands() {
  try {
    const device = new ZktecoJs('127.0.0.1', 4371, 10000);
    
    await device.createSocket();
    console.log('✅ Connected to device');

    // Test device info commands
    console.log('\n--- Device Info Commands ---');
    
    // const vendor = await device.getVendor();
    // console.log('Vendor:', `"${vendor}"`);

    // const deviceName = await device.getDeviceName();
    // console.log('Device Name:', `"${deviceName}"`);

    // const platform = await device.getPlatform();
    // console.log('Platform:', `"${platform}"`);

    // const mac = await device.getMacAddress();
    // console.log('MAC:', `"${mac}"`);

    // const serialNumber = await device.getSerialNumber();
    // console.log('Serial Number:', `"${serialNumber}"`);

    // Test time commands
    console.log('\n--- Time Commands ---');
    
    // const getTime = await device.getTime();
    // console.log('Device Time:', getTime);

    // const setTime = await device.setTime(new Date());
    // console.log('Set Time:', setTime ? 'Success' : 'Failed');

    // Test device control
    console.log('\n--- Device Control Commands ---');
    
    const disable = await device.disableDevice();
    console.log('Disable Device:', disable ? 'Success' : 'Failed');

    const enable = await device.enableDevice();
    console.log('Enable Device:', enable ? 'Success' : 'Failed');

    const freeData = await device.freeData();
    console.log('Free Data:', freeData ? 'Success' : 'Failed');

    // Test user commands
    console.log('\n--- User Commands ---');
    
    const users = await device.getUsers();
    console.log('Users:', users);

    // const addUser = await device.setUser(6, '6', 'Jane Smith', 'password', 0, 0);
    // console.log('Add User:', addUser ? 'Success' : 'Failed');

    // const addUser2 = await device.setUser(7, '7', 'Jane Smith', 'password', 0, 0);
    // console.log('Add User2:', addUser2 ? 'Success' : 'Failed');

    // const deleteUser = await device.deleteUser(2);
    // console.log('Delete User:', deleteUser ? 'Success' : 'Failed');

    // // Test attendance commands
    console.log('\n--- Attendance Commands ---');
    
    // const attendanceSize = await device.getAttendanceSize();
    // console.log('Attendance Size:', attendanceSize);

    const attendances = await device.getAttendances();
    console.log('Attendances:', attendances);

    // const clearAttendanceLog = await device.clearAttendanceLog();
    // console.log('Clear Attendance Log:', clearAttendanceLog ? 'Success' : 'Failed');

    // const clearData = await device.clearData();
    // console.log('Clear Data:', clearData ? 'Success' : 'Failed');

        
    // const attendanceSize2 = await device.getAttendanceSize();
    // console.log('Attendance Size After clear:', attendanceSize2);

    // // Test device info
    // console.log('\n--- Device Info ---');
    
    const info = await device.getInfo();
    console.log('Device Info:', info);

    await device.disconnect();
    console.log('\n✅ All tests completed successfully!');
  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

testAllCommands();