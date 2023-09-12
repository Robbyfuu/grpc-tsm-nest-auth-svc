export default () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  auth: {
    jwtKey: process.env.JWT_KEY,
    supaUrl: process.env.SUPABASE_URL,
    supaKey: process.env.SUPABASE_KEY,
  },
  db: {
    type: 'mysql',
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_DATABASE,
    synchronize: true,
  },
});
