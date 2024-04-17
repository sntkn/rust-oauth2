import nextAppSession, { promisifyStore } from 'next-app-session';
import Redis from 'ioredis';
import RedisStoreFactory from 'connect-redis';

// Your session data type
type SessionData = {
  [key: string]: any;
}

export const session = nextAppSession<SessionData>({
  name: 'BFF_SID', // The cookie name that will hold sid
  secret: 'secret goes here', // Providing a secret will sign the SID before storing it in the cookie, providing extra security
  // Assign Redis store with connection details
  store: promisifyStore(
    new RedisStoreFactory({
      client: new Redis({
        // The redis instance connection details
        host: 'localhost',
        port: 6379
      }),
      prefix: 'app:' // having a prefix is optional but can be usefull if redis service is used by multiple applications
    })
  )
});
