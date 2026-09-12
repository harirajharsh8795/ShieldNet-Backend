import { useEffect, useRef } from "react";
import { useTheme } from "../context/ThemeContext";
import * as THREE from "three";

const DARK_CYAN = new THREE.Color(0x0891b2);
const DARK_BLUE = new THREE.Color(0x2563eb);
const DARK_PALE = new THREE.Color(0xc7f3f8);


export function Sparkle3DBackground() {
  const { theme } = useTheme();
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const isLightTheme = theme === "light";
    // Keep the 3D animation colors identical in both themes: use the original dark-theme palette.
    const CYAN = DARK_CYAN;
    const BLUE = DARK_BLUE;
    const PALE = DARK_PALE;
    const canvas = canvasRef.current;
    if (!canvas) return;

    const renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
      powerPreference: "high-performance",
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);

    const scene = new THREE.Scene();
    scene.background = null;

    const camera = new THREE.PerspectiveCamera(
      50,
      window.innerWidth / window.innerHeight,
      0.1,
      3000,
    );
    camera.position.set(0, 0, 620);

    // Starfield — same structure and motion as the supplied reference.
    const STAR_COUNT = 900;
    const starGeo = new THREE.BufferGeometry();
    const starPos = new Float32Array(STAR_COUNT * 3);
    const starPhase = new Float32Array(STAR_COUNT);
    const starSize = new Float32Array(STAR_COUNT);

    for (let i = 0; i < STAR_COUNT; i++) {
      const i3 = i * 3;
      starPos[i3] = (Math.random() - 0.5) * 2400;
      starPos[i3 + 1] = (Math.random() - 0.5) * 1500;
      starPos[i3 + 2] = -300 - Math.random() * 900;
      starPhase[i] = Math.random() * Math.PI * 2;
      starSize[i] = Math.random() * 1.8 + 0.4;
    }

    starGeo.setAttribute("position", new THREE.BufferAttribute(starPos, 3));
    starGeo.setAttribute("aPhase", new THREE.BufferAttribute(starPhase, 1));
    starGeo.setAttribute("aSize", new THREE.BufferAttribute(starSize, 1));

    const starMat = new THREE.ShaderMaterial({
      uniforms: { uTime: { value: 0 } },
      transparent: true,
      depthWrite: false,
      vertexShader: `
        uniform float uTime;
        attribute float aPhase;
        attribute float aSize;
        varying float vTwinkle;
        void main() {
          vTwinkle = 0.5 + 0.5 * sin(uTime * 1.4 + aPhase * 6.283);
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          gl_PointSize = aSize * (260.0 / -mv.z);
          gl_Position = projectionMatrix * mv;
        }
      `,
      fragmentShader: `
        varying float vTwinkle;
        void main() {
          vec2 uv = gl_PointCoord - 0.5;
          float d = length(uv);
          float a = smoothstep(0.5, 0.0, d);
          vec3 starColor = vec3(${isLightTheme ? "0.78, 0.91, 0.95" : "0.62, 0.86, 0.96"});
          gl_FragColor = vec4(starColor, a * (0.25 + vTwinkle * 0.55));
        }
      `,
    });

    const stars = new THREE.Points(starGeo, starMat);
    scene.add(stars);

    // Four-point sparkle — geometry/animation follows the supplied reference.
    const P = 0.42;
    const R = 200;
    const SP_COUNT = 5200;

    const sparkleRadius = (theta: number) => {
      const c = Math.pow(Math.abs(Math.cos(theta)), P);
      const s = Math.pow(Math.abs(Math.sin(theta)), P);
      return R / Math.pow(c + s, 1 / P);
    };

    const spGeo = new THREE.BufferGeometry();
    const basePos = new Float32Array(SP_COUNT * 3);
    const dispDir = new Float32Array(SP_COUNT * 3);
    const spColor = new Float32Array(SP_COUNT * 3);
    const spSize = new Float32Array(SP_COUNT);
    const spSeed = new Float32Array(SP_COUNT);

    for (let i = 0; i < SP_COUNT; i++) {
      const theta = Math.random() * Math.PI * 2;
      const rMax = sparkleRadius(theta);
      const r = rMax * Math.sqrt(Math.random());
      const x = Math.cos(theta) * r;
      const y = Math.sin(theta) * r;
      const z = (Math.random() - 0.5) * 26;
      const i3 = i * 3;

      basePos[i3] = x;
      basePos[i3 + 1] = y;
      basePos[i3 + 2] = z;

      const rand3 = new THREE.Vector3(
        Math.random() - 0.5,
        Math.random() - 0.5,
        Math.random() - 0.5,
      );
      const radial = new THREE.Vector3(x, y, z).normalize();
      const dir = radial.multiplyScalar(0.75).add(rand3.multiplyScalar(0.6)).normalize();

      dispDir[i3] = dir.x;
      dispDir[i3 + 1] = dir.y;
      dispDir[i3 + 2] = dir.z;

      const n =
        Math.sin(theta * 5.0 + r * 0.05) *
          Math.sin(theta * 2.3 - r * 0.04) +
        Math.sin(theta * 9.1 + 1.7) * 0.3;
      const edge = r / rMax;

      let col: THREE.Color;
      if (n > 0.25 || edge > 0.86) {
        col = CYAN.clone().lerp(BLUE, Math.random() * 0.5);
      } else if (n > -0.1) {
        col = PALE.clone().lerp(BLUE, 0.25 + Math.random() * 0.3);
      } else {
        col = PALE.clone();
      }

      spColor[i3] = col.r;
      spColor[i3 + 1] = col.g;
      spColor[i3 + 2] = col.b;
      spSize[i] = 1.3 + Math.random() * 2.2;
      spSeed[i] = Math.random() * Math.PI * 2;
    }

    spGeo.setAttribute("position", new THREE.BufferAttribute(basePos.slice(), 3));
    spGeo.setAttribute("color", new THREE.BufferAttribute(spColor, 3));
    spGeo.setAttribute("aSize", new THREE.BufferAttribute(spSize, 1));

    const spMat = new THREE.ShaderMaterial({
      uniforms: { uFade: { value: 1.0 } },
      vertexColors: true,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      vertexShader: `
        attribute float aSize;
        varying vec3 vColor;
        void main() {
          vColor = color;
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          gl_PointSize = aSize * (420.0 / -mv.z);
          gl_Position = projectionMatrix * mv;
        }
      `,
      fragmentShader: `
        uniform float uFade;
        varying vec3 vColor;
        void main() {
          vec2 uv = gl_PointCoord - 0.5;
          float d = length(uv);
          float a = smoothstep(0.5, 0.05, d);
          gl_FragColor = vec4(vColor, a * uFade * 0.9);
        }
      `,
    });

    const sparkleGroup = new THREE.Group();
    const sparklePoints = new THREE.Points(spGeo, spMat);
    sparkleGroup.add(sparklePoints);
    scene.add(sparkleGroup);

    // Cursor smoke/comet trail — purple in the reference, adapted to Sentinel blue/cyan.
    const makeSmokeTexture = () => {
      const size = 256;
      const c = document.createElement("canvas");
      c.width = c.height = size;
      const ctx = c.getContext("2d");
      if (!ctx) return new THREE.Texture();

      const g = ctx.createRadialGradient(
        size / 2,
        size / 2,
        0,
        size / 2,
        size / 2,
        size / 2,
      );
      g.addColorStop(0, "rgba(34,211,238,0.48)");
      g.addColorStop(0.35, "rgba(37,99,235,0.28)");
      g.addColorStop(0.7, "rgba(30,64,175,0.10)");
      g.addColorStop(1, "rgba(15,23,42,0)");
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, size, size);

      const texture = new THREE.CanvasTexture(c);
      texture.needsUpdate = true;
      return texture;
    };

    const smokeTex = makeSmokeTexture();
    const TRAIL_POOL = 140;
    const trailGroup = new THREE.Group();
    trailGroup.position.z = 60;
    scene.add(trailGroup);

    type TrailParticle = {
      sprite: THREE.Sprite;
      active: boolean;
      age: number;
      life: number;
      x: number;
      y: number;
      vx: number;
      vy: number;
      size0: number;
      size1: number;
      rot: number;
      rotSpeed: number;
    };

    const trailParticles: TrailParticle[] = [];

    for (let i = 0; i < TRAIL_POOL; i++) {
      const spr = new THREE.Sprite(
        new THREE.SpriteMaterial({
          map: smokeTex,
          transparent: true,
          depthWrite: false,
          blending: THREE.NormalBlending,
          opacity: 0,
        }),
      );
      spr.visible = false;
      trailGroup.add(spr);
      trailParticles.push({
        sprite: spr,
        active: false,
        age: 0,
        life: 1,
        x: 0,
        y: 0,
        vx: 0,
        vy: 0,
        size0: 10,
        size1: 40,
        rot: 0,
        rotSpeed: 0,
      });
    }

    let trailCursor = 0;

    const spawnTrailParticle = (x: number, y: number, vxHint: number, vyHint: number) => {
      const p = trailParticles[trailCursor];
      trailCursor = (trailCursor + 1) % TRAIL_POOL;
      p.active = true;
      p.age = 0;
      p.life = 0.9 + Math.random() * 0.5;
      p.x = x + (Math.random() - 0.5) * 8;
      p.y = y + (Math.random() - 0.5) * 8;
      p.vx = vxHint * (0.15 + Math.random() * 0.15) + (Math.random() - 0.5) * 6;
      p.vy =
        vyHint * (0.15 + Math.random() * 0.15) +
        (Math.random() - 0.5) * 6 +
        4;
      p.size0 = 14 + Math.random() * 10;
      p.size1 = p.size0 + 55 + Math.random() * 45;
      p.rot = Math.random() * Math.PI * 2;
      p.rotSpeed = (Math.random() - 0.5) * 0.6;
      p.sprite.visible = true;
    };

    const mouseNDC = new THREE.Vector2(0, 0);
    const mouseTarget = new THREE.Vector2(0, 0);
    const raycaster = new THREE.Raycaster();
    const trailPlane = new THREE.Plane(new THREE.Vector3(0, 0, 1), -60);
    const mouseWorld = new THREE.Vector3();
    const prevMouseWorld = new THREE.Vector3();
    let mouseHasMoved = false;
    let trailInitialized = false;
    let scrollT = 0;

    const onMouseMove = (event: MouseEvent) => {
      mouseTarget.x = (event.clientX / window.innerWidth) * 2 - 1;
      mouseTarget.y = -(event.clientY / window.innerHeight) * 2 + 1;
      mouseHasMoved = true;
    };

    const updateScroll = () => {
      const h = window.innerHeight;
      scrollT = Math.min(Math.max(window.scrollY / (h * 0.9), 0), 1);
    };

    const onResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };

    window.addEventListener("mousemove", onMouseMove, { passive: true });
    window.addEventListener("scroll", updateScroll, { passive: true });
    window.addEventListener("resize", onResize);
    updateScroll();

    const clock = new THREE.Clock();
    const posAttr = spGeo.attributes.position;
    let prevT = 0;
    let frame = 0;
    let running = true;

    const animate = () => {
      if (!running) return;
      frame = requestAnimationFrame(animate);

      const t = clock.getElapsedTime();
      const dt = Math.min(t - prevT, 0.05);
      prevT = t;

      starMat.uniforms.uTime.value = t;
      stars.rotation.y = t * 0.003;

      mouseNDC.x += (mouseTarget.x - mouseNDC.x) * 0.05;
      mouseNDC.y += (mouseTarget.y - mouseNDC.y) * 0.05;

      sparkleGroup.rotation.y = t * 0.35 + Math.sin(t * 0.12) * 0.6;
      sparkleGroup.rotation.x = Math.sin(t * 0.17) * 0.35;
      sparkleGroup.rotation.z = Math.sin(t * 0.08) * 0.08;
      sparkleGroup.rotation.y += mouseNDC.x * 0.25;
      sparkleGroup.rotation.x += -mouseNDC.y * 0.18;

      const breathe = Math.pow(0.5 - 0.5 * Math.cos(t * 0.35), 2.2);
      const disperse = Math.min(breathe + scrollT * 1.6, 1.8);

      for (let i = 0; i < SP_COUNT; i++) {
        const i3 = i * 3;
        const wob = Math.sin(t * 1.6 + spSeed[i]) * 3.0;
        const push =
          disperse *
          (140 + wob * 4) *
          (0.4 + Math.abs(Math.sin(spSeed[i] * 3.0 + i)) * 0.6);

        posAttr.array[i3] =
          basePos[i3] +
          dispDir[i3] * push +
          Math.sin(t * 0.6 + spSeed[i]) * 2.0;
        posAttr.array[i3 + 1] =
          basePos[i3 + 1] +
          dispDir[i3 + 1] * push +
          Math.cos(t * 0.5 + spSeed[i]) * 2.0;
        posAttr.array[i3 + 2] =
          basePos[i3 + 2] + dispDir[i3 + 2] * push;
      }

      posAttr.needsUpdate = true;
      spMat.uniforms.uFade.value = Math.max(0.15, 1.0 - scrollT * 0.85);
      sparkleGroup.position.y = scrollT * -40;
      sparkleGroup.scale.setScalar(1 - scrollT * 0.12);

      raycaster.setFromCamera(mouseNDC, camera);
      raycaster.ray.intersectPlane(trailPlane, mouseWorld);

      if (mouseHasMoved) {
        if (!trailInitialized) {
          prevMouseWorld.copy(mouseWorld);
          trailInitialized = true;
        }

        const dx = mouseWorld.x - prevMouseWorld.x;
        const dy = mouseWorld.y - prevMouseWorld.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const spawnCount = Math.min(6, 1 + Math.floor(dist / 6));

        for (let s = 0; s < spawnCount; s++) {
          const lerp = spawnCount > 1 ? s / (spawnCount - 1) : 1;
          const px = prevMouseWorld.x + dx * lerp;
          const py = prevMouseWorld.y + dy * lerp;
          spawnTrailParticle(
            px,
            py,
            (dx / Math.max(dt, 0.001)) * 0.02,
            (dy / Math.max(dt, 0.001)) * 0.02,
          );
        }
        prevMouseWorld.copy(mouseWorld);
      }

      for (const p of trailParticles) {
        if (!p.active) continue;
        p.age += dt;

        if (p.age >= p.life) {
          p.active = false;
          p.sprite.visible = false;
          continue;
        }

        const f = p.age / p.life;
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        p.vx *= 0.94;
        p.vy *= 0.94;
        p.rot += p.rotSpeed * dt;

        const size = p.size0 + (p.size1 - p.size0) * f;
        const opacity = Math.sin(Math.min(f, 1) * Math.PI) * (isLightTheme ? 0.14 : 0.6);
        p.sprite.position.set(p.x, p.y, 0);
        p.sprite.scale.set(size, size, 1);
        p.sprite.material.rotation = p.rot;
        p.sprite.material.opacity = opacity;
      }

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      running = false;
      cancelAnimationFrame(frame);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("scroll", updateScroll);
      window.removeEventListener("resize", onResize);

      starGeo.dispose();
      starMat.dispose();
      spGeo.dispose();
      spMat.dispose();
      smokeTex.dispose();

      trailParticles.forEach((p) => p.sprite.material.dispose());
      renderer.dispose();
    };
  }, [theme]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="sparkle-3d-background"
    />
  );
}
