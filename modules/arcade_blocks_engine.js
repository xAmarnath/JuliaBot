(function(root){
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
  function rotateAt(board,shape,x,y) {
    const next=rotate(shape);
    for(const [dx,dy] of [[0,0],[-1,0],[1,0],[-2,0],[2,0],[-3,0],[3,0],[0,-1],[0,-2],[0,-3]])
      if(fits(board,next,x+dx,y+dy))return {shape:next,x:x+dx,y:y+dy};
    return null;
  }
  root.Arcade={...root.Arcade,shapes,rotate,fits,lock,rotateAt};
})(globalThis);
