/* Pure game rules, shared by the widget and offline regression tests. */
(function (root) {
  const lines = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  function winner(b) {
    for (const [a,c,d] of lines) if (b[a] && b[a] === b[c] && b[a] === b[d]) return b[a];
    return b.every(Boolean) ? 'draw' : '';
  }
  function bestMove(b, player = 'O') {
    function score(board, turn, depth) {
      const end = winner(board);
      if (end) return end === 'draw' ? 0 : end === player ? 10-depth : depth-10;
      const scores = [];
      for (let i=0;i<9;i++) if (!board[i]) { board[i]=turn; scores.push(score(board,turn==='X'?'O':'X',depth+1)); board[i]=''; }
      return turn === player ? Math.max(...scores) : Math.min(...scores);
    }
    if (winner(b)) return -1;
    let best = -Infinity, move = -1;
    for (const i of [4,0,2,6,8,1,3,5,7]) if (!b[i]) {
      b[i]=player; const value=score(b,player==='X'?'O':'X',0); b[i]='';
      if (value>best) { best=value; move=i; }
    }
    return move;
  }
  function mergeLine(line) {
    const values = line.filter(Boolean), out=[];
    let score=0;
    for (let i=0;i<values.length;i++) {
      if (values[i]===values[i+1]) { out.push(values[i]*2); score+=values[i]*2; i++; }
      else out.push(values[i]);
    }
    return {line:out.concat(Array(line.length-out.length).fill(0)),score};
  }
  function slide(board, direction) {
    if (!['left','right','up','down'].includes(direction)) return {board:board.slice(),score:0,changed:false};
    const out=board.slice(); let score=0;
    for(let r=0;r<4;r++) {
      let ids=Array.from({length:4},(_,c)=>direction==='left'||direction==='right'?r*4+c:c*4+r);
      if(direction==='right'||direction==='down') ids.reverse();
      const merged=mergeLine(ids.map(i=>board[i])); score+=merged.score;
      ids.forEach((id,j)=>out[id]=merged.line[j]);
    }
    return {board:out,score,changed:out.some((v,i)=>v!==board[i])};
  }
  function spawn(board, random=Math.random) {
    const out=board.slice(), empty=out.map((v,i)=>v? -1:i).filter(i=>i>=0);
    if(empty.length) out[empty[Math.min(empty.length-1,Math.floor(random()*empty.length))]]=random()<0.9?2:4;
    return out;
  }
  function canMove(board) { return ['left','right','up','down'].some(d=>slide(board,d).changed); }
  const shapes = [[[1,1,1,1]],[[2,2],[2,2]],[[0,3,0],[3,3,3]],[[0,4,4],[4,4,0]],[[5,5,0],[0,5,5]],[[6,0,0],[6,6,6]],[[0,0,7],[7,7,7]]];
  function rotate(shape) { return shape[0].map((_,x)=>shape.map(row=>row[x]).reverse()); }
  function fits(board,shape,x,y) { return shape.every((row,dy)=>row.every((v,dx)=>!v||(x+dx>=0&&x+dx<10&&y+dy>=0&&y+dy<board.length&&!board[y+dy][x+dx]))); }
  function lock(board,shape,x,y) {
    const out=board.map(row=>row.slice());
    shape.forEach((row,dy)=>row.forEach((v,dx)=>{if(v)out[y+dy][x+dx]=v;}));
    const remaining=out.filter(row=>row.some(v=>!v)), cleared=out.length-remaining.length;
    while(remaining.length<out.length) remaining.unshift(Array(10).fill(0));
    return {board:remaining,cleared};
  }
  root.Arcade={winner,bestMove,mergeLine,slide,spawn,canMove,shapes,rotate,fits,lock};
})(globalThis);
