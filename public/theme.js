/**
 * 季節自動テーマシステム (Seasonal Theme Engine)
 * - 春 (3-5月): 桜 (Sakura)
 * - 夏 (6-8月): 海 (Ocean)
 * - 秋 (9-11月): 紅葉 (Autumn Leaves)
 * - 冬 (12-2月): 雪 (Snow)
 */

(function () {
    const SEASONS = {
        default: { name: 'デフォルト', iconSrc: '/assets/theme-icons/default.png', description: '通常のグリーンテーマ' },
        spring: { name: '春 (桜)', iconSrc: '/assets/theme-icons/spring.png', description: '桜が舞う春のテーマ' },
        summer: { name: '夏 (海)', iconSrc: '/assets/theme-icons/summer.png', description: '波と気泡が揺らめく夏のテーマ' },
        autumn: { name: '秋 (紅葉)', iconSrc: '/assets/theme-icons/autumn.png', description: '紅葉が舞い散る秋のテーマ' },
        winter: { name: '冬 (雪)', iconSrc: '/assets/theme-icons/winter.png', description: '粉雪が降り注ぐ冬のテーマ' }
    };

    function getAutoSeason() {
        const month = new Date().getMonth() + 1; // 1〜12
        if (month >= 3 && month <= 5) return 'spring';
        if (month >= 6 && month <= 8) return 'summer';
        if (month >= 9 && month <= 11) return 'autumn';
        return 'winter';
    }

    function getCurrentSetting() {
        const setting = localStorage.getItem('urlshorter_season_setting') || 'auto';
        return ['auto', 'default', 'spring', 'summer', 'autumn', 'winter'].includes(setting) ? setting : 'auto';
    }

    function getActiveSeason() {
        const setting = getCurrentSetting();
        return setting === 'auto' ? getAutoSeason() : setting;
    }

    // テーマ設定の適用
    function applySeasonTheme(season) {
        document.body.setAttribute('data-season', season);
        const metaThemeColor = document.querySelector('meta[name="theme-color"]');
        const themeColors = {
            default: '#34d399',
            spring: '#f472b6',
            summer: '#38bdf8',
            autumn: '#fb923c',
            winter: '#93c5fd'
        };
        if (metaThemeColor) {
            metaThemeColor.setAttribute('content', themeColors[season] || '#34d399');
        }

        // UI表示の更新
        updateBadgeUI();
        if (window.particleEngine) {
            window.particleEngine.setSeason(season);
        }
    }

    function updateBadgeUI() {
        const setting = getCurrentSetting();
        const active = getActiveSeason();
        const iconEl = document.getElementById('seasonIcon');
        const nameEl = document.getElementById('seasonName');
        const info = SEASONS[active];

        if (iconEl && nameEl && info) {
            if (info.iconSrc) {
                iconEl.innerHTML = `<img src="${info.iconSrc}" alt="" class="theme-badge-icon" aria-hidden="true">`;
            } else {
                iconEl.textContent = info.icon || '';
            }
            nameEl.textContent = info.name;
        }
    }

    window.setSeason = function (setting) {
        localStorage.setItem('urlshorter_season_setting', setting);
        const active = setting === 'auto' ? getAutoSeason() : setting;
        applySeasonTheme(active);
        const menu = document.getElementById('seasonDropdownMenu');
        if (menu) menu.classList.add('hidden');
    };

    window.toggleSeasonMenu = function () {
        const menu = document.getElementById('seasonDropdownMenu');
        if (menu) menu.classList.toggle('hidden');
    };

    // クリック外れでメニューを閉じる
    document.addEventListener('click', (e) => {
        const container = document.getElementById('seasonSelectorContainer');
        const menu = document.getElementById('seasonDropdownMenu');
        if (container && menu && !container.contains(e.target)) {
            menu.classList.add('hidden');
        }
    });

    // ======== パーティクル描画エンジン ========
    class ParticleEngine {
        constructor(canvas) {
            this.canvas = canvas;
            this.ctx = canvas.getContext('2d');
            this.particles = [];
            this.season = getActiveSeason();
            this.width = 0;
            this.height = 0;
            this.animId = null;
            this.isActive = true;

            this.init();
        }

        init() {
            this.resize();
            window.addEventListener('resize', () => this.resize());
            document.addEventListener('visibilitychange', () => {
                this.isActive = !document.hidden;
                if (this.isActive) this.loop();
            });

            this.createParticles();
            this.loop();
        }

        resize() {
            this.width = this.canvas.width = window.innerWidth;
            this.height = this.canvas.height = window.innerHeight;
            if (this.particles.length > 0) {
                this.createParticles();
            }
        }

        setSeason(newSeason) {
            if (this.season !== newSeason) {
                this.season = newSeason;
                this.createParticles();
            }
        }

        createParticles() {
            this.particles = [];
            if (this.season === 'default') return;

            const isMobile = this.width < 768;
            let count = isMobile ? 20 : 40;

            if (this.season === 'winter') count = isMobile ? 35 : 70; // 雪は少し多め

            for (let i = 0; i < count; i++) {
                this.particles.push(this.createParticle(true));
            }
        }

        createParticle(initial = false) {
            const y = initial ? Math.random() * this.height : -20;
            const x = Math.random() * this.width;

            if (this.season === 'spring') {
                // 桜の花びら
                return {
                    x,
                    y,
                    size: 8 + Math.random() * 8,
                    speedY: 1.0 + Math.random() * 1.5,
                    speedX: 0.5 + Math.random() * 1.0,
                    angle: Math.random() * Math.PI * 2,
                    angleSpeed: (Math.random() - 0.5) * 0.03,
                    swayAngle: Math.random() * Math.PI * 2,
                    swaySpeed: 0.02 + Math.random() * 0.02,
                    swayDist: 15 + Math.random() * 25,
                    flipAngle: Math.random() * Math.PI,
                    flipSpeed: 0.02 + Math.random() * 0.03,
                    opacity: 0.5 + Math.random() * 0.4,
                    color: ['#fbcfe8', '#f472b6', '#fda4af', '#fecdd3'][Math.floor(Math.random() * 4)]
                };
            } else if (this.season === 'summer') {
                // 海の気泡 & 水中キラキラ
                return {
                    x,
                    y: initial ? Math.random() * this.height : this.height + 20, // 下から上へ上昇
                    size: 3 + Math.random() * 8,
                    speedY: -(0.6 + Math.random() * 1.2),
                    speedX: (Math.random() - 0.5) * 0.5,
                    swayAngle: Math.random() * Math.PI * 2,
                    swaySpeed: 0.03 + Math.random() * 0.02,
                    opacity: 0.3 + Math.random() * 0.5,
                    glow: Math.random() > 0.5
                };
            } else if (this.season === 'autumn') {
                // 紅葉（もみじ & イチョウ）
                return {
                    x,
                    y,
                    size: 10 + Math.random() * 10,
                    speedY: 1.2 + Math.random() * 1.8,
                    speedX: 0.5 + Math.random() * 1.2,
                    angle: Math.random() * Math.PI * 2,
                    angleSpeed: (Math.random() - 0.5) * 0.04,
                    swayAngle: Math.random() * Math.PI * 2,
                    swaySpeed: 0.02 + Math.random() * 0.03,
                    swayDist: 20 + Math.random() * 30,
                    flipAngle: Math.random() * Math.PI,
                    flipSpeed: 0.03 + Math.random() * 0.03,
                    opacity: 0.7 + Math.random() * 0.3,
                    type: Math.random() > 0.4 ? 'maple' : 'ginkgo', // もみじ または イチョウ
                    color: ['#ea580c', '#f97316', '#dc2626', '#f59e0b', '#b45309'][Math.floor(Math.random() * 5)]
                };
            } else if (this.season === 'winter') {
                // 冬の雪
                return {
                    x,
                    y,
                    size: 1.5 + Math.random() * 3.5,
                    speedY: 0.8 + Math.random() * 1.8,
                    speedX: (Math.random() - 0.5) * 0.5,
                    swayAngle: Math.random() * Math.PI * 2,
                    swaySpeed: 0.01 + Math.random() * 0.02,
                    swayDist: 10 + Math.random() * 15,
                    opacity: 0.4 + Math.random() * 0.6,
                    isStar: Math.random() > 0.75
                };
            }

            return null;
        }

        drawCherryPetal(p) {
            const ctx = this.ctx;
            ctx.save();
            ctx.translate(p.x, p.y);
            ctx.rotate(p.angle);
            ctx.scale(Math.cos(p.flipAngle), 1);

            ctx.beginPath();
            ctx.moveTo(0, -p.size);
            ctx.bezierCurveTo(p.size * 0.8, -p.size * 0.5, p.size * 0.7, p.size * 0.8, 0, p.size);
            ctx.bezierCurveTo(-p.size * 0.7, p.size * 0.8, -p.size * 0.8, -p.size * 0.5, 0, -p.size);
            ctx.closePath();

            ctx.fillStyle = p.color;
            ctx.globalAlpha = p.opacity;
            ctx.fill();
            ctx.restore();
        }

        drawBubble(p) {
            const ctx = this.ctx;
            ctx.save();
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(56, 189, 248, 0.15)';
            ctx.strokeStyle = 'rgba(186, 230, 253, 0.6)';
            ctx.lineWidth = 1;
            ctx.globalAlpha = p.opacity;
            ctx.fill();
            ctx.stroke();

            // ハイライトハイライト
            ctx.beginPath();
            ctx.arc(p.x - p.size * 0.3, p.y - p.size * 0.3, p.size * 0.25, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
            ctx.fill();

            ctx.restore();
        }

        drawMapleLeaf(p) {
            const ctx = this.ctx;
            ctx.save();
            ctx.translate(p.x, p.y);
            ctx.rotate(p.angle);
            ctx.scale(Math.cos(p.flipAngle), 1);

            ctx.fillStyle = p.color;
            ctx.globalAlpha = p.opacity;

            if (p.type === 'ginkgo') {
                // イチョウ型
                ctx.beginPath();
                ctx.moveTo(0, 0);
                ctx.arc(0, -p.size * 0.5, p.size * 0.7, 0.2 * Math.PI, 0.8 * Math.PI, true);
                ctx.closePath();
                ctx.fill();
            } else {
                // もみじ型 (星型をベースにした紅葉の葉)
                const s = p.size * 0.7;
                ctx.beginPath();
                ctx.moveTo(0, -s);
                ctx.lineTo(s * 0.3, -s * 0.3);
                ctx.lineTo(s, -s * 0.2);
                ctx.lineTo(s * 0.4, s * 0.2);
                ctx.lineTo(s * 0.6, s * 0.8);
                ctx.lineTo(0, s * 0.4);
                ctx.lineTo(-s * 0.6, s * 0.8);
                ctx.lineTo(-s * 0.4, s * 0.2);
                ctx.lineTo(-s, -s * 0.2);
                ctx.lineTo(-s * 0.3, -s * 0.3);
                ctx.closePath();
                ctx.fill();
            }

            ctx.restore();
        }

        drawSnowflake(p) {
            const ctx = this.ctx;
            ctx.save();
            ctx.globalAlpha = p.opacity;
            ctx.fillStyle = '#ffffff';

            if (p.isStar && p.size > 2.5) {
                // 結晶風
                ctx.translate(p.x, p.y);
                ctx.strokeStyle = '#e0f2fe';
                ctx.lineWidth = 1;
                for (let i = 0; i < 3; i++) {
                    ctx.beginPath();
                    ctx.moveTo(-p.size, 0);
                    ctx.lineTo(p.size, 0);
                    ctx.stroke();
                    ctx.rotate(Math.PI / 3);
                }
            } else {
                // まるい粉雪
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fill();
            }

            ctx.restore();
        }

        update() {
            for (let i = 0; i < this.particles.length; i++) {
                const p = this.particles[i];

                if (this.season === 'summer') {
                    // 下から上へ
                    p.y += p.speedY;
                    p.swayAngle += p.swaySpeed;
                    p.x += Math.sin(p.swayAngle) * 0.5 + p.speedX;

                    if (p.y < -30) {
                        this.particles[i] = this.createParticle(false);
                    }
                } else {
                    // 上から下へ
                    p.y += p.speedY;
                    p.swayAngle += p.swaySpeed;
                    p.x += Math.sin(p.swayAngle) * 0.8 + (p.speedX || 0);

                    if (p.angleSpeed) p.angle += p.angleSpeed;
                    if (p.flipSpeed) p.flipAngle += p.flipSpeed;

                    if (p.y > this.height + 30 || p.x < -40 || p.x > this.width + 40) {
                        this.particles[i] = this.createParticle(false);
                    }
                }
            }
        }

        draw() {
            this.ctx.clearRect(0, 0, this.width, this.height);

            for (const p of this.particles) {
                if (this.season === 'spring') {
                    this.drawCherryPetal(p);
                } else if (this.season === 'summer') {
                    this.drawBubble(p);
                } else if (this.season === 'autumn') {
                    this.drawMapleLeaf(p);
                } else if (this.season === 'winter') {
                    this.drawSnowflake(p);
                }
            }
        }

        loop() {
            if (!this.isActive) return;
            this.update();
            this.draw();
            this.animId = requestAnimationFrame(() => this.loop());
        }
    }

    // DOMロード時に初期化
    function setupSeasonSystem() {
        const active = getActiveSeason();
        applySeasonTheme(active);

        // Canvasの生成 (未存在の場合)
        if (!document.getElementById('seasonCanvas')) {
            const canvas = document.createElement('canvas');
            canvas.id = 'seasonCanvas';
            document.body.appendChild(canvas);
            window.particleEngine = new ParticleEngine(canvas);
        }

        // アンビエントグラデーションの生成 (未存在の場合)
        if (!document.querySelector('.season-ambient')) {
            const ambient = document.createElement('div');
            ambient.className = 'season-ambient';
            document.body.prepend(ambient);
        }

        updateBadgeUI();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupSeasonSystem);
    } else {
        setupSeasonSystem();
    }
})();
