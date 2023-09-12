// import { Injectable, Logger } from '@nestjs/common';
// import axios from 'axios';

// @Injectable()
// export class PublicIpService {
//   private readonly logger = new Logger(PublicIpService.name);

//   async getPublicIP(): Promise<string> {
//     try {
//       const response = await axios.get('https://api64.ipify.org?format=json');
//       const ip = response.data.ip;
//       this.logger.log(`La dirección IP pública del servidor es: ${ip}`);
//       return ip;
//     } catch (error) {
//       this.logger.error('Hubo un error al obtener la dirección IP', error);
//       throw new Error('Hubo un error al obtener la dirección IP');
//     }
//   }
// }
