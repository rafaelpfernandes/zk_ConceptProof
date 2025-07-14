
    const canvas = document.getElementById("cryptoRain");
    const ctx = canvas.getContext("2d");

    const fontSize = 14;
    const chars = "ABCDEF0123456789=+/".split("");
    let drops; 

    function initializeCanvas() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const columns = canvas.width / fontSize;
      drops = Array(Math.floor(columns)).fill(1);
    }

    initializeCanvas();

    window.addEventListener('resize', initializeCanvas);

    function draw() {
      ctx.fillStyle = "rgba(255, 255, 255, 0.05)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#BF1E2E";
      ctx.font = fontSize + "px monospace";

      drops.forEach((y, i) => {
        const text = chars[Math.floor(Math.random() * chars.length)];
        const x = i * fontSize;
        ctx.fillText(text, x, y * fontSize);

        if (y * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      });
    }

    setInterval(draw, 60);

