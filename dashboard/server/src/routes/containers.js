'use strict';

const express = require('express');
const docker = require('../lib/docker');
const fleet = require('../lib/fleet');
const { seedVulhub } = require('../lib/seedVulhub');
const { pool } = require('../db');

const router = express.Router();

// ---------- Fleet management page ----------
router.get('/containers', async (req, res, next) => {
  try {
    const dockerAvailable = await docker.isDockerAvailable();
    let containers = [];
    if (dockerAvailable) {
      // includeAll so Vulhub recipe containers (named after the recipe dir,
      // not vb-*) come back too — they're what the recipe status table below
      // is built from.
      containers = await docker.listContainers({ includeAll: true });
    }

    // Build a status map by container name
    const statusMap = {};
    for (const c of containers) {
      statusMap[c.name] = c;
    }

    // Builtin labs with status
    const builtinLabs = fleet.BUILTIN_SERVICES.map((s) => ({
      ...s,
      container_status: statusMap[s.container] || null,
    }));

    // Infra with status
    const infra = fleet.INFRA_SERVICES.map((s) => ({
      ...s,
      container_status: statusMap[s.container] || null,
    }));

    // Vulhub state
    const vulhubCloned = fleet.isVulhubCloned();
    let categories = [];
    let activeRecipes = [];
    let recipeFleet = [];
    let seededCount = 0;
    if (vulhubCloned) {
      categories = await fleet.listCategories();
      // Live Docker state is the source of truth for what's actually up; the
      // state files vulhub.sh keeps are the fallback, so a recipe whose
      // containers were removed out-of-band still offers a Stop to clean up.
      recipeFleet = await fleet.getRecipeFleet(containers);
      const live = new Set(recipeFleet.map((r) => r.target));
      activeRecipes = [...new Set([...live, ...fleet.getActiveRecipes()])].sort();
      // Check how many vulhub labs are seeded in DB
      const [[{ cnt }]] = await pool.query("SELECT COUNT(*) AS cnt FROM labs WHERE kind='vulhub'");
      seededCount = cnt;
    }

    // Keyed by target so the per-category recipe rows can show live status
    // without a second pass over the container list.
    const recipeStatus = {};
    for (const r of recipeFleet) recipeStatus[r.target] = r;

    // Anything left over: not builtin, not infra, and not traceable to a
    // recipe (a hand-started container, or one whose recipe was deleted).
    const knownNames = new Set([
      ...fleet.BUILTIN_SERVICES.map((s) => s.container),
      ...fleet.INFRA_SERVICES.map((s) => s.container),
      'vb-dashboard', 'vb-dashboard-db',
    ]);
    const recipeContainerNames = new Set(
      recipeFleet.flatMap((r) => r.containers.map((c) => c.name))
    );
    // Same address treatment as the recipe rows — these are the containers
    // someone started outside the dashboard, so where to reach them is the
    // main thing the page can tell you about them. On a user-defined network
    // the container name resolves, so that's the host to show.
    const otherContainers = containers
      .filter((c) => !knownNames.has(c.name) && !recipeContainerNames.has(c.name))
      .map((c) => ({ ...c, host: c.name, endpoints: fleet.buildEndpoints(c.name, c) }));

    res.render('containers', {
      dockerAvailable,
      builtinLabs,
      infra,
      vulhubCloned,
      categories,
      activeRecipes,
      recipeFleet,
      recipeStatus,
      otherContainers,
      seededCount,
      flash: req.query.flash || null,
    });
  } catch (err) {
    next(err);
  }
});

// ---------- Builtin lab actions ----------
router.post('/containers/builtin/:service/start', async (req, res, next) => {
  try {
    const svc = fleet.BUILTIN_SERVICES.find((s) => s.service === req.params.service)
              || fleet.INFRA_SERVICES.find((s) => s.service === req.params.service);
    if (!svc) return res.status(404).render('error', { message: 'Unknown service.' });

    // Try starting existing container first, fall back to docker compose up
    try {
      await docker.startContainer(svc.container);
    } catch {
      await fleet.startBuiltin(svc.service);
    }
    res.redirect('/containers?flash=Started ' + svc.name);
  } catch (err) {
    next(err);
  }
});

router.post('/containers/builtin/:service/stop', async (req, res, next) => {
  try {
    const svc = fleet.BUILTIN_SERVICES.find((s) => s.service === req.params.service)
              || fleet.INFRA_SERVICES.find((s) => s.service === req.params.service);
    if (!svc) return res.status(404).render('error', { message: 'Unknown service.' });
    await docker.stopContainer(svc.container);
    res.redirect('/containers?flash=Stopped ' + svc.name);
  } catch (err) {
    if (err.statusCode === 304) return res.redirect('/containers');
    next(err);
  }
});

router.post('/containers/builtin/:service/restart', async (req, res, next) => {
  try {
    const svc = fleet.BUILTIN_SERVICES.find((s) => s.service === req.params.service)
              || fleet.INFRA_SERVICES.find((s) => s.service === req.params.service);
    if (!svc) return res.status(404).render('error', { message: 'Unknown service.' });
    await docker.restartContainer(svc.container);
    res.redirect('/containers?flash=Restarted ' + svc.name);
  } catch (err) {
    next(err);
  }
});

// ---------- Container actions (any container by name) ----------
router.post('/containers/:name/start', async (req, res, next) => {
  try {
    await docker.startContainer(req.params.name);
    res.redirect('/containers');
  } catch (err) {
    if (err.statusCode === 304) return res.redirect('/containers');
    next(err);
  }
});

router.post('/containers/:name/stop', async (req, res, next) => {
  try {
    await docker.stopContainer(req.params.name);
    res.redirect('/containers');
  } catch (err) {
    if (err.statusCode === 304) return res.redirect('/containers');
    next(err);
  }
});

router.post('/containers/:name/restart', async (req, res, next) => {
  try {
    await docker.restartContainer(req.params.name);
    res.redirect('/containers');
  } catch (err) {
    next(err);
  }
});

// ---------- Vulhub actions ----------
router.post('/containers/vulhub/clone', async (req, res, next) => {
  try {
    if (!fleet.isVulhubCloned()) {
      await fleet.cloneVulhub();
    }
    // Auto-seed ground-truth after clone
    const stats = await seedVulhub(fleet.getVulhubDir());
    res.redirect(`/containers?flash=Vulhub cloned and seeded: ${stats.created} labs created, ${stats.updated} updated, ${stats.total} recipes`);
  } catch (err) {
    next(err);
  }
});

router.post('/containers/vulhub/seed', async (req, res, next) => {
  try {
    if (!fleet.isVulhubCloned()) {
      return res.status(400).render('error', { message: 'Clone Vulhub first.' });
    }
    const stats = await seedVulhub(fleet.getVulhubDir());
    res.redirect(`/containers?flash=Ground-truth seeded: ${stats.created} new, ${stats.updated} updated, ${stats.errors} errors out of ${stats.total} recipes`);
  } catch (err) {
    next(err);
  }
});

router.post('/containers/vulhub/recipe/up', async (req, res, next) => {
  try {
    const target = req.body.target;
    if (!target) return res.status(400).render('error', { message: 'No recipe specified.' });
    await fleet.upRecipe(target);
    res.redirect('/containers?flash=Started recipe: ' + target);
  } catch (err) {
    next(err);
  }
});

router.post('/containers/vulhub/recipe/down', async (req, res, next) => {
  try {
    const target = req.body.target;
    if (!target) return res.status(400).render('error', { message: 'No recipe specified.' });
    await fleet.downRecipe(target);
    res.redirect('/containers?flash=Stopped recipe: ' + target);
  } catch (err) {
    next(err);
  }
});

router.post('/containers/vulhub/category/up', async (req, res, next) => {
  try {
    const category = req.body.category;
    if (!category) return res.status(400).render('error', { message: 'No category specified.' });
    await fleet.upCategory(category);
    res.redirect('/containers?flash=Started category: ' + category);
  } catch (err) {
    next(err);
  }
});

router.post('/containers/vulhub/category/down', async (req, res, next) => {
  try {
    const category = req.body.category;
    if (!category) return res.status(400).render('error', { message: 'No category specified.' });
    await fleet.downCategory(category);
    res.redirect('/containers?flash=Stopped category: ' + category);
  } catch (err) {
    next(err);
  }
});

router.post('/containers/vulhub/down-all', async (req, res, next) => {
  try {
    await fleet.downAll();
    res.redirect('/containers?flash=All Vulhub recipes torn down');
  } catch (err) {
    next(err);
  }
});

// ---------- JSON API for recipes list (used by recipe picker) ----------
router.get('/api/vulhub/recipes', async (req, res, next) => {
  try {
    const category = req.query.category || null;
    const recipes = await fleet.listRecipes(category);
    res.json({ recipes });
  } catch (err) {
    next(err);
  }
});

router.get('/api/containers', async (req, res, next) => {
  try {
    const available = await docker.isDockerAvailable();
    if (!available) return res.json({ error: 'Docker not available', containers: [] });
    const containers = await docker.listContainers({ includeAll: true });
    res.json({ containers });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
