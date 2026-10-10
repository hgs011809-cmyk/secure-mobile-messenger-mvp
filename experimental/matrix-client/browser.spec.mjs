import {test,expect} from '@playwright/test';
test('real browser initializes Rust crypto and keeps only durable deletion metadata',async({page})=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 // No homeserver exists in this test. Never send synthetic credentials to a real API.
 await page.route('http://127.0.0.1:18008/**',route=>route.abort());
 await page.goto('/');await page.getByRole('button',{name:'로컬 검증 실행'}).click();
 await expect(page.locator('#result')).toContainText('PASS:',{timeout:45000});
 expect(errors).toEqual([]);
});
