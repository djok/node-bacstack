'use strict';

const baEnum      = require('./enum');

const DefaultBACnetPort = 47808;

module.exports.encode = (buffer, func, msgLength, forwardedFrom) => {
  buffer[0] = baEnum.BVLL_TYPE_BACNET_IP;
  // buffer[1] set below
  buffer[2] = (msgLength & 0xFF00) >> 8;
  buffer[3] = (msgLength & 0x00FF) >> 0;
  if (forwardedFrom) {
    // This is always a FORWARDED_NPDU regardless of the 'func' parameter.
    buffer[1] = baEnum.BvlcResultPurpose.FORWARDED_NPDU;
    const [ipstr, portstr] = forwardedFrom.split(':');
    const port = parseInt(portstr) || DefaultBACnetPort;
    const ip = ipstr.split('.');
    buffer[4] = parseInt(ip[0]);
    buffer[5] = parseInt(ip[1]);
    buffer[6] = parseInt(ip[2]);
    buffer[7] = parseInt(ip[3]);
    buffer[8] = (port & 0xFF00) >> 8;
    buffer[9] = (port & 0x00FF) >> 0;
    return 6 + baEnum.BVLC_HEADER_LENGTH;
  }
  buffer[1] = func;
  return baEnum.BVLC_HEADER_LENGTH;
};

module.exports.decode = (buffer, offset) => {
  let len;
  const func = buffer[1];
  const msgLength = (buffer[2] << 8) | (buffer[3] << 0);
  if (buffer[0] !== baEnum.BVLL_TYPE_BACNET_IP || buffer.length !== msgLength) return;
  switch (func) {
    case baEnum.BvlcResultPurpose.BVLC_RESULT:
    case baEnum.BvlcResultPurpose.ORIGINAL_UNICAST_NPDU:
    case baEnum.BvlcResultPurpose.ORIGINAL_BROADCAST_NPDU:
    case baEnum.BvlcResultPurpose.DISTRIBUTE_BROADCAST_TO_NETWORK:
    case baEnum.BvlcResultPurpose.REGISTER_FOREIGN_DEVICE:
    case baEnum.BvlcResultPurpose.READ_FOREIGN_DEVICE_TABLE:
    case baEnum.BvlcResultPurpose.DELETE_FOREIGN_DEVICE_TABLE_ENTRY:
    case baEnum.BvlcResultPurpose.READ_BROADCAST_DISTRIBUTION_TABLE:
    case baEnum.BvlcResultPurpose.WRITE_BROADCAST_DISTRIBUTION_TABLE:
    case baEnum.BvlcResultPurpose.READ_BROADCAST_DISTRIBUTION_TABLE_ACK:
    case baEnum.BvlcResultPurpose.READ_FOREIGN_DEVICE_TABLE_ACK:
      len = 4;
      break;
    case baEnum.BvlcResultPurpose.FORWARDED_NPDU:
      len = 10;
      break;
    case baEnum.BvlcResultPurpose.SECURE_BVLL:
      // unimplemented
      return;
    default:
      return;
  }
  return {
    len: len,
    func: func,
    msgLength: msgLength
  };
};
