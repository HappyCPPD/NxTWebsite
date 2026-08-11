const nav = document.getElementById('nav');
const navToggle = document.getElementById('navToggle');
const mobilePanel = document.getElementById('mobilePanel');

navToggle.addEventListener('click', () => {
  const isOpen = nav.classList.toggle('is-open');
  navToggle.setAttribute('aria-expanded', String(isOpen));
});

mobilePanel.querySelectorAll('a').forEach((link) => {
  link.addEventListener('click', () => {
    nav.classList.remove('is-open');
    navToggle.setAttribute('aria-expanded', 'false');
  });
});

const onScroll = () => nav.classList.toggle('is-stuck', window.scrollY > 8);
window.addEventListener('scroll', onScroll, { passive: true });
onScroll();

const navLinks = Array.from(document.querySelectorAll('.nav-links a'));
const sections = navLinks
  .map((link) => document.querySelector(link.getAttribute('href')))
  .filter(Boolean);

if ('IntersectionObserver' in window && sections.length) {
  const spy = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        navLinks.forEach((link) => {
          link.classList.toggle('is-active', link.getAttribute('href') === `#${entry.target.id}`);
        });
      });
    },
    { rootMargin: '-45% 0px -50% 0px' }
  );
  sections.forEach((section) => spy.observe(section));
}

const navClock = document.getElementById('navClock');

if (navClock) {
  const pad = (n) => String(n).padStart(2, '0');
  const tick = () => {
    const now = new Date();
    navClock.textContent = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  };
  tick();
  setInterval(tick, 1000);
}

const joinForm = document.getElementById('joinForm');
const formStatus = document.getElementById('formStatus');
const submitBtn = joinForm.querySelector('button[type="submit"]');

joinForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const honeypot = joinForm.querySelector('#_gotcha');
  if (honeypot && honeypot.value) {
    joinForm.reset();
    return;
  }

  submitBtn.disabled = true;
  submitBtn.classList.add('is-sending');
  submitBtn.querySelector('.btn-label').textContent = 'Sending';
  formStatus.textContent = '';
  formStatus.classList.remove('is-ok');

  try {
    const response = await fetch(joinForm.action, {
      method: 'POST',
      body: new FormData(joinForm),
      headers: { Accept: 'application/json' },
    });

    if (response.ok) {
      formStatus.textContent = 'Application sent. Expect a reply within a week.';
      formStatus.classList.add('is-ok');
      joinForm.reset();
    } else {
      formStatus.textContent = 'That did not send. Try again, or reach us on Discord.';
    }
  } catch (err) {
    formStatus.textContent = 'That did not send. Try again, or reach us on Discord.';
  } finally {
    submitBtn.disabled = false;
    submitBtn.classList.remove('is-sending');
    submitBtn.querySelector('.btn-label').textContent = 'Send application';
  }
});

const gameOut = document.getElementById('gameOut');

if (gameOut) {
  const gameForm = document.getElementById('gameForm');
  const gameCmd = document.getElementById('gameCmd');
  const gamePrompt = document.getElementById('gamePrompt');
  const gameTitle = document.getElementById('gameTitle');
  const gameReset = document.getElementById('gameReset');

  const PW = { svc: 'Br0k3n_r0t4t10n_2019' };
  const FLAG = 'nxt{su1d_b1n4ry_w4s_th3_wh0l3_p4th}';

  const dir = (children, o = {}) => ({ type: 'd', children, mode: 'drwxr-xr-x', owner: 'root', ...o });
  const file = (body, o = {}) => ({ type: 'f', body, mode: '-rw-r--r--', owner: 'root', ...o });

  const buildFs = () => dir({
    home: dir({
      guest: dir({
        'readme.txt': file(
          'sandbox box #4 — rebuilt from the 2019 image.\n' +
          'nothing on this host is production. break it however you like.\n',
          { owner: 'guest' }
        ),
        '.bash_history': file(
          'ls -la ~/.cache\n' +
          'base64 -d\n' +
          'su svc\n' +
          'rm -rf /tmp/stage\n' +
          'history -c\n',
          { owner: 'guest' }
        ),
        '.cache': dir({
          'session.b64': file('c3ZjOkJyMGszbl9yMHQ0dDEwbl8yMDE5\n', { owner: 'guest' }),
        }, { owner: 'guest' }),
        notes: dir({
          'todo.md': file(
            '- [ ] rotate the service account password (overdue since 2019)\n' +
            '- [ ] audit anything still running setuid\n',
            { owner: 'guest' }
          ),
        }, { owner: 'guest' }),
      }, { owner: 'guest' }),
      svc: dir({
        'deploy.log': file(
          'rotate ok  /var/backups/db-01.tar.gz\n' +
          'rotate ok  /var/backups/db-02.tar.gz\n' +
          'rotate ERR /root/.ssh — refused, running unprivileged\n',
          { owner: 'svc' }
        ),
      }, { owner: 'svc', mode: 'drwx------', read: ['svc', 'root'] }),
    }),
    etc: dir({
      passwd: file(
        'root:x:0:0:root:/root:/bin/bash\n' +
        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n' +
        'svc:x:998:998:backup service:/home/svc:/bin/bash\n' +
        'guest:x:1000:1000:guest:/home/guest:/bin/bash\n'
      ),
      shadow: file('root:$6$rounds=656000$mMqCJ0kR$1c...truncated\n', {
        mode: '-rw-------', read: ['root'],
      }),
      crontab: file(
        'SHELL=/bin/sh\n' +
        'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\n' +
        '\n' +
        '*/10 * * * * root /usr/local/bin/dump --rotate /var/backups\n'
      ),
    }),
    usr: dir({
      local: dir({
        bin: dir({
          dump: file('\x7fELF\x02\x01\x01 ... stripped\n', {
            mode: '-rwsr-x---', owner: 'root', group: 'svc',
            suid: true, exec: ['svc', 'root'],
          }),
        }),
      }),
    }),
    var: dir({
      backups: dir({
        'db-01.tar.gz': file('\x1f\x8b\x08 ... binary\n'),
      }),
      log: dir({
        'auth.log': file(
          'sshd[812]:  Accepted publickey for guest from 10.0.0.4 port 51410\n' +
          'su[904]:    (to svc) admin on pts/0\n' +
          'sudo[911]:  guest : user NOT in sudoers ; COMMAND=/bin/cat /root/flag.txt\n' +
          'cron[1102]: (root) CMD (/usr/local/bin/dump --rotate /var/backups)\n'
        ),
      }),
    }),
    root: dir({
      'flag.txt': file(FLAG + '\n', { mode: '-rw-------', read: ['root'] }),
    }, { mode: 'drwx------', read: ['root'] }),
    tmp: dir({}, { mode: 'drwxrwxrwx' }),
  });

  const state = { fs: buildFs(), user: 'guest', cwd: ['home', 'guest'], pending: null };
  const history = [];
  let historyIdx = 0;

  const HOMES = { root: ['root'], svc: ['home', 'svc'], guest: ['home', 'guest'] };

  const canRead = (node) => !node.read || node.read.includes(state.user);
  const canExec = (node) => Array.isArray(node.exec) && node.exec.includes(state.user);

  const cwdLabel = () => {
    const home = '/' + HOMES[state.user].join('/');
    const path = state.cwd.length ? '/' + state.cwd.join('/') : '/';
    if (path === home) return '~';
    if (path.startsWith(home + '/')) return '~' + path.slice(home.length);
    return path;
  };

  const syncPrompt = () => {
    gamePrompt.textContent = `${state.user}@sandbox:${cwdLabel()}${state.user === 'root' ? '#' : '$'}`;
    gameTitle.textContent = `${state.user}@sandbox: ${cwdLabel()}`;
    gamePrompt.classList.toggle('is-root', state.user === 'root');
  };

  const print = (text, cls) => {
    const line = document.createElement('p');
    line.className = 'term-line game-line' + (cls ? ' ' + cls : '');
    line.textContent = text;
    gameOut.appendChild(line);
    gameOut.scrollTop = gameOut.scrollHeight;
  };

  const echo = (raw) => {
    const line = document.createElement('p');
    line.className = 'term-line game-line';
    const p = document.createElement('span');
    p.className = 'prompt' + (state.user === 'root' ? ' is-root' : '');
    p.textContent = gamePrompt.textContent;
    const c = document.createElement('span');
    c.className = 'cmd';
    c.textContent = ' ' + raw;
    line.append(p, c);
    gameOut.appendChild(line);
    gameOut.scrollTop = gameOut.scrollHeight;
  };

  const resolve = (input) => {
    let segs;
    if (input === '~' || input.startsWith('~/')) segs = HOMES[state.user].concat(input.slice(2).split('/'));
    else if (input.startsWith('/')) segs = input.split('/');
    else segs = state.cwd.concat(input.split('/'));

    const out = [];
    for (const seg of segs) {
      if (seg === '' || seg === '.') continue;
      if (seg === '..') out.pop();
      else out.push(seg);
    }
    return out;
  };

  const lookup = (segs) => {
    let node = state.fs;
    for (const seg of segs) {
      if (node.type !== 'd' || !node.children[seg]) return null;
      node = node.children[seg];
    }
    return node;
  };

  const walk = (segs, node, hit) => {
    hit(segs, node);
    if (node.type !== 'd' || !canRead(node)) return;
    Object.keys(node.children).forEach((name) => walk(segs.concat(name), node.children[name], hit));
  };

  const pathOf = (segs) => '/' + segs.join('/');

  const readFile = (target, asRoot) => {
    const node = lookup(resolve(target));
    if (!node) return { err: 'No such file or directory' };
    if (node.type === 'd') return { err: 'Is a directory' };
    if (!asRoot && !canRead(node)) return { err: 'Permission denied' };
    return { body: node.body };
  };

  const emit = (body) => {
    body.replace(/\n$/, '').split('\n').forEach((l) => {
      print(l, l.includes('nxt{') ? 'game-flag' : 'term-out');
    });
  };

  const binaries = {
    dump(args) {
      const target = args.find((a) => !a.startsWith('-'));
      if (!target) return print('usage: dump [--rotate] <path>', 'term-out');

      const res = readFile(target, true);
      if (res.err) return print(`dump: ${target}: ${res.err}`, 'game-err');
      emit(res.body);
    },
  };

  const findBinary = (name) => {
    for (const p of ['/usr/local/bin/', '/usr/bin/']) {
      const node = lookup(resolve(p + name));
      if (node && node.type === 'f') return { node, path: p + name };
    }
    return null;
  };

  const commands = {
    help() {
      [
        ['ls [-a] [-l] [path]', 'list directory contents'],
        ['cd <path>', 'change directory'],
        ['cat <file>', 'concatenate a file to stdout'],
        ['find <path> [-name x] [-perm -4000]', 'search the tree'],
        ['grep [-r] <pattern> <path>', 'search file contents'],
        ['base64 [-d] <file>', 'encode or decode'],
        ['pwd / whoami / id', 'session info'],
        ['su <user>', 'switch user'],
        ['sudo <cmd>', 'run as another user'],
        ['clear', 'clear the screen'],
      ].forEach(([n, d]) => print(`  ${n.padEnd(38)}${d}`, 'term-out'));
    },

    pwd() { print(state.cwd.length ? '/' + state.cwd.join('/') : '/', 'term-out'); },
    whoami() { print(state.user, 'term-out'); },

    id() {
      const ids = { root: 'uid=0(root) gid=0(root) groups=0(root)',
        svc: 'uid=998(svc) gid=998(svc) groups=998(svc)',
        guest: 'uid=1000(guest) gid=1000(guest) groups=1000(guest)' };
      print(ids[state.user], 'term-out');
    },

    clear() { gameOut.replaceChildren(); },

    ls(args) {
      const flags = args.filter((a) => a.startsWith('-')).join('');
      const showAll = flags.includes('a');
      const long = flags.includes('l');
      const target = args.find((a) => !a.startsWith('-')) || '.';
      const node = lookup(resolve(target));

      if (!node) return print(`ls: cannot access '${target}': No such file or directory`, 'game-err');
      if (!canRead(node)) return print(`ls: cannot open directory '${target}': Permission denied`, 'game-err');
      if (node.type === 'f') return print(target, 'term-out');

      const names = Object.keys(node.children).filter((n) => showAll || !n.startsWith('.'));
      if (!names.length && !showAll) return;

      if (long) {
        print(`total ${names.length}`, 'term-out');
        names.forEach((name) => {
          const c = node.children[name];
          const grp = c.group || c.owner || 'root';
          print(`${c.mode}  ${(c.owner || 'root').padEnd(6)}${grp.padEnd(6)}  ${name}${c.type === 'd' ? '/' : ''}`, 'term-out');
        });
        return;
      }

      print(names.map((n) => n + (node.children[n].type === 'd' ? '/' : '')).join('   '), 'term-out');
    },

    cd(args) {
      const target = args[0] || '~';
      const segs = resolve(target);
      const node = lookup(segs);

      if (!node) return print(`cd: ${target}: No such file or directory`, 'game-err');
      if (node.type !== 'd') return print(`cd: ${target}: Not a directory`, 'game-err');
      if (!canRead(node)) return print(`cd: ${target}: Permission denied`, 'game-err');

      state.cwd = segs;
      syncPrompt();
    },

    cat(args) {
      if (!args.length) return print('cat: missing operand', 'game-err');
      const res = readFile(args[0], false);
      if (res.err) return print(`cat: ${args[0]}: ${res.err}`, 'game-err');
      emit(res.body);
    },

    base64(args) {
      const decode = args.some((a) => a === '-d' || a === '--decode');
      const target = args.find((a) => !a.startsWith('-'));
      if (!target) return print('base64: missing operand', 'game-err');

      const res = readFile(target, false);
      if (res.err) return print(`base64: ${target}: ${res.err}`, 'game-err');

      const raw = res.body.trim();
      try {
        print(decode ? atob(raw) : btoa(raw), 'term-out');
      } catch (err) {
        print('base64: invalid input', 'game-err');
      }
    },

    find(args) {
      const start = args.find((a) => !a.startsWith('-')) || '.';
      const nameIdx = args.indexOf('-name');
      const pattern = nameIdx > -1 ? args[nameIdx + 1] : null;
      const permIdx = args.indexOf('-perm');
      const wantSuid = permIdx > -1 && /4000/.test(args[permIdx + 1] || '');

      const segs = resolve(start);
      const node = lookup(segs);
      if (!node) return print(`find: '${start}': No such file or directory`, 'game-err');

      const matches = [];
      walk(segs, node, (s, n) => {
        const name = s[s.length - 1] || '/';
        if (wantSuid && !n.suid) return;
        if (pattern) {
          const re = new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
          if (!re.test(name)) return;
        }
        matches.push(pathOf(s));
      });

      if (!matches.length) return;
      matches.forEach((m) => print(m, 'term-out'));
    },

    grep(args) {
      const recursive = args.some((a) => a.startsWith('-') && a.includes('r'));
      const rest = args.filter((a) => !a.startsWith('-'));
      const pattern = rest[0];
      const target = rest[1] || '.';
      if (!pattern) return print('usage: grep [-r] <pattern> <path>', 'game-err');

      const segs = resolve(target);
      const node = lookup(segs);
      if (!node) return print(`grep: ${target}: No such file or directory`, 'game-err');

      const scan = (s, n) => {
        if (n.type !== 'f' || !canRead(n)) return;
        n.body.split('\n').forEach((line) => {
          if (!line.includes(pattern)) return;
          print(recursive || n !== node ? `${pathOf(s)}: ${line}` : line, 'term-out');
        });
      };

      if (node.type === 'f') scan(segs, node);
      else if (recursive) walk(segs, node, scan);
      else print(`grep: ${target}: Is a directory`, 'game-err');
    },

    su(args) {
      const target = args[0] || 'root';
      if (!HOMES[target]) return print(`su: user ${target} does not exist`, 'game-err');
      if (target === state.user) return print(`su: already ${target}`, 'game-err');

      state.pending = target;
      gameCmd.type = 'password';
      gamePrompt.textContent = 'Password:';
    },

    sudo() {
      print(`${state.user} is not in the sudoers file. This incident has been reported.`, 'game-err');
    },

    exit() {
      if (state.user === 'guest') return print('exit: not a login shell', 'game-err');
      state.user = 'guest';
      state.cwd = HOMES.guest.slice();
      syncPrompt();
      print('logout', 'term-out');
    },
  };

  const submitPassword = (value) => {
    const target = state.pending;
    state.pending = null;
    gameCmd.type = 'text';

    if (PW[target] && value === PW[target]) {
      state.user = target;
      state.cwd = HOMES[target].slice();
    } else {
      print('su: Authentication failure', 'game-err');
    }
    syncPrompt();
  };

  const tokenize = (input) => {
    const out = [];
    const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let m;
    while ((m = re.exec(input)) !== null) {
      out.push(m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3]);
    }
    return out;
  };

  const run = (raw) => {
    const input = raw.trim();
    if (!input) return;

    const [name, ...args] = tokenize(input);

    if (commands[name]) return commands[name](args);

    const bin = name.includes('/')
      ? (() => { const n = lookup(resolve(name)); return n ? { node: n, path: name } : null; })()
      : findBinary(name);

    if (bin && bin.node.type === 'f') {
      const key = bin.path.split('/').pop();
      if (!canExec(bin.node)) return print(`${name}: Permission denied`, 'game-err');
      if (binaries[key]) return binaries[key](args);
      return print(`${name}: cannot execute binary file`, 'game-err');
    }

    print(`${name}: command not found`, 'game-err');
  };

  const banner = () => {
    print('Debian GNU/Linux 12 (sandbox)  ·  kernel 6.1.0-nxt', 'game-head');
    print('Last login: Tue Aug 11 03:14:07 2026 from 10.0.0.4', 'term-out');
    print('`help` lists the available commands.', 'term-out');
    print('', 'term-out');
  };

  gameForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const value = gameCmd.value;
    gameCmd.value = '';

    if (state.pending) {
      echo('•'.repeat(Math.min(value.length, 24)));
      submitPassword(value);
      return;
    }

    echo(value);
    if (value.trim()) {
      history.push(value);
      historyIdx = history.length;
    }
    run(value);
  });

  gameCmd.addEventListener('keydown', (e) => {
    if (state.pending) return;

    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (historyIdx > 0) gameCmd.value = history[--historyIdx];
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIdx < history.length - 1) {
        gameCmd.value = history[++historyIdx];
      } else {
        historyIdx = history.length;
        gameCmd.value = '';
      }
    }
  });

  gameOut.addEventListener('click', () => {
    if (!window.getSelection().toString()) gameCmd.focus();
  });

  gameReset.addEventListener('click', () => {
    state.fs = buildFs();
    state.user = 'guest';
    state.cwd = HOMES.guest.slice();
    state.pending = null;
    gameCmd.type = 'text';
    gameCmd.value = '';
    history.length = 0;
    historyIdx = 0;
    gameOut.replaceChildren();
    syncPrompt();
    banner();
    gameCmd.focus();
  });

  syncPrompt();
  banner();
}

console.log(
  '%cnxt_ctfs%c you found the console. the flag is one decode away — check data-x on #term.',
  'background:#e6293f;color:#fff;font-weight:700;padding:2px 6px;border-radius:3px',
  'color:#9d98a6'
);
