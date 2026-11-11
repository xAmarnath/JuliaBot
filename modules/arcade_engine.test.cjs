const {test}=require('node:test'),assert=require('node:assert/strict');
for(const game of ['ttt','2048','blocks'])require('./arcade_'+game+'_engine.js'); const A=globalThis.Arcade;
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

test('2048 supports every row and column on 4, 5 and 6 grids without mutating input',()=>{
  for(const n of [4,5,6])for(const direction of ['left','right','up','down']) {
    const b=Array(n*n).fill(0), horizontal=['left','right'].includes(direction);
    for(let line=0;line<n;line++){
      b[horizontal?line*n:line]=2;
      b[horizontal?line*n+1:n+line]=2;
    }
    const copy=b.slice(),result=A.slide(b,direction);
    const expected=Array(n*n).fill(0);
    for(let line=0;line<n;line++)expected[horizontal?line*n+(direction==='right'?n-1:0):(direction==='down'?n*(n-1):0)+line]=4;
    assert.deepEqual(result.board,expected,`${n} ${direction}`);
    assert.deepEqual(b,copy);assert.equal(result.score,n*4);assert.equal(result.changed,true);
    const full=Array.from({length:n*n},(_,i)=>(Math.floor(i/n)+i%n)%2?2:4);
    assert.equal(A.canMove(full),false);
    full[n*n-1]=full[n*n-2];assert.equal(A.canMove(full),true);
    assert.deepEqual(A.spawn(Array(n*n).fill(2)),Array(n*n).fill(2));
  }
});

test('Tetris wall and floor kicks stay legal and reject blocked rotation',()=>{
  const board=Array.from({length:20},()=>Array(10).fill(0));
  const vertical=A.rotate(A.shapes[0]);
  const wall=A.rotateAt(board,vertical,9,5);
  assert.ok(wall);assert.equal(wall.x,6);assert.ok(A.fits(board,wall.shape,wall.x,wall.y));
  const floor=A.rotateAt(board,A.shapes[2],4,18);
  assert.ok(floor);assert.equal(floor.y,17);assert.ok(A.fits(board,floor.shape,floor.x,floor.y));
  const low=A.rotateAt(board,A.shapes[0],4,19);
  assert.ok(low);assert.equal(low.y,16);assert.ok(A.fits(board,low.shape,low.x,low.y));
  assert.equal(A.rotateAt(Array.from({length:20},()=>Array(10).fill(1)),A.shapes[2],4,5),null);
});
