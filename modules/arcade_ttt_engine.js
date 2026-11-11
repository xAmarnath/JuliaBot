(function(root){
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
  root.Arcade={...root.Arcade,lines,winner,bestMove};
})(globalThis);
