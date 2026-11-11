const {test}=require('node:test'),assert=require('node:assert/strict');
require('./arcade_engine.js'); const A=globalThis.Arcade;
test('machine never loses against any human move sequence',()=>{
  function play(board){const end=A.winner(board);assert.notEqual(end,'X');if(end)return;for(let i=0;i<9;i++)if(!board[i]){const b=board.slice();b[i]='X';assert.notEqual(A.winner(b),'X');if(!A.winner(b))b[A.bestMove(b)]='O';play(b)}}
  play(Array(9).fill(''));
});
test('2048 merges only once per tile, in all directions',()=>{
  assert.deepEqual(A.mergeLine([2,2,2,2]),{line:[4,4,0,0],score:8});
  assert.deepEqual(A.mergeLine([4,0,4,8]),{line:[8,8,0,0],score:8});
  const b=[2,2,0,0,...Array(12).fill(0)];
  assert.deepEqual(A.slide(b,'right').board.slice(0,4),[0,0,0,4]);
  assert.deepEqual(A.slide([2,0,0,0,2,...Array(11).fill(0)],'down').board.slice(12),[4,0,0,0]);
  assert.equal(A.slide([2,...Array(15).fill(0)],'left').changed,false);
  assert.equal(A.canMove([2,4,2,4,4,2,4,2,2,4,2,4,4,2,4,2]),false);
  assert.equal(A.spawn(b,()=>0).filter(Boolean).length,3);
});
test('blocks collision, rotation and simultaneous line clear',()=>{
  const b=Array.from({length:16},()=>Array(10).fill(0)),square=A.shapes[1];
  assert.equal(A.fits(b,square,-1,0),false);assert.equal(A.fits(b,square,9,0),false);assert.equal(A.fits(b,square,0,15),false);
  for(const shape of A.shapes)assert.deepEqual(A.rotate(A.rotate(A.rotate(A.rotate(shape)))),shape);
  b[14].fill(1);b[15].fill(1);b[14][0]=b[14][1]=b[15][0]=b[15][1]=0;
  const result=A.lock(b,square,0,14);assert.equal(result.cleared,2);assert.equal(result.board.length,16);assert.ok(result.board.every(row=>row.every(v=>!v)));assert.equal(b[14][0],0);
});
