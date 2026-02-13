import fs from 'fs';
import os from 'os';
import { configType } from '../types';

export function getConfig() {
  let config_json: configType;
  try {
    config_json = JSON.parse(process.env.CONFIG);
  } catch {
    try {
      config_json = JSON.parse(fs.readFileSync('./config.json').toString());
    } catch {
      console.log('[Main]', `Config Error`);
      config_json = {} as any;
    }
  }
  let part_warp: any = {};
  if (config_json['warp']) {
    part_warp = {
      ...part_warp,
      warp_secretKey: config_json['warp']['key'] || '',
      warp_ipv4: config_json['warp']['ipv4'] || '172.16.0.2',
      warp_ipv6: config_json['warp']['ipv6'] || '',
      warp_reserved: [0, 0, 0],
      warp_publicKey: config_json['warp']['pubkey'] || 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
      warp_endpoint: config_json['warp']['endpoint'] || '162.159.192.1:2408' || 'engage.cloudflareclient.com:2408',
      add_ipv4: config_json['warp']['add4'] || false,
      add_ipv6: config_json['warp']['add6'] || false,
      warp_routing: config_json['warp']['routing'] || 'auto',
    };
    if (config_json['warp']['reserved']) {
      function decodeClientId(clientId) {
        const decodedBuffer = Buffer.from(clientId, 'base64');
        const hexString = decodedBuffer.toString('hex');
        const hexPairs = hexString.match(/.{1,2}/g) || [];
        const decimalArray = hexPairs.map(hex => parseInt(hex, 16));
        return decimalArray;
      }
      part_warp.warp_reserved = decodeClientId(config_json['warp']['reserved']);
    }
  }
  let part_cloudflared: any = {
    cloudflared_path:
      config_json['cloudflared_path'] || (os.platform() == 'win32' ? './cloudflared.exe' : './cloudflared'),
  };
  if (config_json['cloudflared']) {
    part_cloudflared = {
      ...part_cloudflared,
      use_cloudflared: config_json['cloudflared']['use'] || false,
      // [auto]/quic/http2
      cloudflared_protocol: config_json['cloudflared']['protocol'] || '',
      // none/us
      cloudflared_region: config_json['cloudflared']['region'] || '',
      cloudflared_access_token: config_json['cloudflared']['token'] || '',
    };
  }
  let part_tls = {};
  if (config_json['tls']) {
    part_tls = {
      ...part_tls,
      use_tls: config_json['tls']['use'] || false,
      // please use base64 encode
      tls_key: Buffer.from(config_json['tls']['key'], 'base64').toString() || '',
      tls_cert: Buffer.from(config_json['tls']['cert'], 'base64').toString() || '',
    };
  }
  return {
    // core
    core_path: config_json['core_path'] || (os.platform() == 'win32' ? './core.exe' : './core'),
    port: config_json['port'] || 3000,
    middle_port: config_json['middle_port'] || 58515,
    disable_exit_protect: config_json['disable_exit_protect'] || false,
    protocol: config_json['protocol'] || 'dmxlc3M=',
    // Tested: ws/xhttp
    network: config_json['network'] || 'ws',
    uuid: config_json['uuid'] || crypto.randomUUID(),
    path: config_json['path'] || '/api',
    display_web_entry: config_json['display_web_entry'] || false,
    // tls
    ...part_tls,
    // warp
    ...part_warp,
    // cloudflared
    ...part_cloudflared,
  };
}
