// Pure orchestration only; native server, DB and clock are never replaced.
export const REPEATED_STARTUP_PLAN=Object.freeze({killCount:3,startupHoldMs:200,startupProcessBudgetMs:1000});
export async function crashPendingSequence({repeated,adapter}){
 if(typeof repeated!=='boolean')throw new Error('invalid_plan');
 const plan=repeated?REPEATED_STARTUP_PLAN:{killCount:1,startupHoldMs:0};
 let kills=0,interruptions=0;
 for(let n=0;n<plan.killCount;n++){
  if(n>0){await adapter.startSame();await adapter.requireHomeserverProcess(REPEATED_STARTUP_PLAN.startupProcessBudgetMs);await adapter.hold(REPEATED_STARTUP_PLAN.startupHoldMs);interruptions++;}
  await adapter.killAndRequire137NonOOM();kills++;
  await adapter.requireStoppedSameCiphertext();
 }
 await adapter.startSame();
 return {kills,startupInterruptions:interruptions};
}
