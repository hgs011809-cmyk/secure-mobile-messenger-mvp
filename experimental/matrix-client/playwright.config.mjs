import {defineConfig} from '@playwright/test';
export default defineConfig({testMatch:'browser.spec.mjs',timeout:60000,use:{baseURL:'http://127.0.0.1:19461',headless:true},webServer:{command:'node serve.mjs',url:'http://127.0.0.1:19461',reuseExistingServer:false},reporter:'list'});
