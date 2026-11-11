(function(root){
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
    const n=Math.sqrt(board.length);
    if(!Number.isInteger(n)||n<2)throw new RangeError('Board must be square');
    const out=board.slice(); let score=0;
    for(let r=0;r<n;r++) {
      let ids=Array.from({length:n},(_,c)=>direction==='left'||direction==='right'?r*n+c:c*n+r);
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
  root.Arcade={...root.Arcade,mergeLine,slide,spawn,canMove};
})(globalThis);
