// discord-security-bot/index.js
require('dotenv').config();
const { Client, GatewayIntentBits, EmbedBuilder, PermissionFlagsBits, AuditLogEvent, Partials, SlashCommandBuilder, REST, Routes } = require('discord.js');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildModeration,
    GatewayIntentBits.GuildWebhooks
  ],
  partials: [Partials.Message, Partials.Channel, Partials.GuildMember]
});

const SECURITY_CONFIG = {
  MAX_MESSAGES_PER_MINUTE: 10,
  MAX_CHANNELS_DELETED: 3,
  MAX_ROLES_DELETED: 2,
  MAX_BANS_PER_HOUR: 5,
  LOG_CHANNEL_NAME: process.env.LOG_CHANNEL || 'security-logs',
  AUTO_BAN_ENABLED: true,
  PHANTOM_BOT_DETECTION: true,
  BACKUP_INTERVAL: 1000 * 60 * 60 * 6, // 6 hours
  LOCKDOWN_TIMEOUT: 1000 * 60 * 30 // 30 minutes
};

// Variables de stockage
let messageCounts = new Map();
let roleBackup = new Map();
let channelBackup = new Map();
let memberBackup = new Map();
let actionCounts = new Map();
let lockdownStatus = new Map();
let whitelist = [process.env.OWNER_ID];
let trustedRoles = new Set();

// ================================
// SYSTÈME DE SAUVEGARDE COMPLET
// ================================

async function backupGuildData(guild) {
  try {
    // Sauvegarde des rôles
    const roles = guild.roles.cache
      .filter(r => r.permissions.has(PermissionFlagsBits.Administrator) || r.permissions.has(PermissionFlagsBits.ManageGuild))
      .map(r => ({
        id: r.id,
        name: r.name,
        permissions: r.permissions.bitfield.toString(),
        color: r.color,
        position: r.position,
        mentionable: r.mentionable,
        hoist: r.hoist
      }));
    roleBackup.set(guild.id, roles);

    // Sauvegarde des canaux importants
    const channels = guild.channels.cache
      .filter(c => c.type === 0 || c.type === 2) // Text et Voice
      .map(c => ({
        id: c.id,
        name: c.name,
        type: c.type,
        position: c.position,
        parentId: c.parentId,
        topic: c.topic,
        nsfw: c.nsfw,
        permissions: c.permissionOverwrites.cache.map(p => ({
          id: p.id,
          type: p.type,
          allow: p.allow.bitfield.toString(),
          deny: p.deny.bitfield.toString()
        }))
      }));
    channelBackup.set(guild.id, channels);

    // Sauvegarde des membres importants
    const importantMembers = guild.members.cache
      .filter(m => m.permissions.has(PermissionFlagsBits.Administrator) || m.permissions.has(PermissionFlagsBits.ManageGuild))
      .map(m => ({
        id: m.id,
        roles: m.roles.cache.map(r => r.id),
        nickname: m.nickname
      }));
    memberBackup.set(guild.id, importantMembers);

    console.log(`[BACKUP] Données sauvegardées pour ${guild.name} - ${roles.length} rôles, ${channels.length} canaux, ${importantMembers.length} membres`);
  } catch (error) {
    console.error(`[BACKUP ERROR] ${guild.name}:`, error);
  }
}

// ================================
// SYSTÈME DE RESTAURATION
// ================================

async function restoreGuildData(guild, type = 'all') {
  try {
    const logChannel = getLogChannel(guild);
    
    if (type === 'all' || type === 'roles') {
      const savedRoles = roleBackup.get(guild.id);
      if (savedRoles) {
        for (const roleData of savedRoles) {
          const existingRole = guild.roles.cache.get(roleData.id);
          if (!existingRole) {
            await guild.roles.create({
              name: roleData.name,
              permissions: BigInt(roleData.permissions),
              color: roleData.color,
              hoist: roleData.hoist,
              mentionable: roleData.mentionable,
              reason: 'Restauration automatique de sécurité'
            });
          }
        }
        log(guild, '🔄 **Rôles restaurés** depuis la sauvegarde');
      }
    }

    if (type === 'all' || type === 'channels') {
      const savedChannels = channelBackup.get(guild.id);
      if (savedChannels) {
        for (const channelData of savedChannels) {
          const existingChannel = guild.channels.cache.get(channelData.id);
          if (!existingChannel) {
            const newChannel = await guild.channels.create({
              name: channelData.name,
              type: channelData.type,
              parent: channelData.parentId,
              topic: channelData.topic,
              nsfw: channelData.nsfw,
              reason: 'Restauration automatique de sécurité'
            });
            
            // Restaurer les permissions
            for (const perm of channelData.permissions) {
              await newChannel.permissionOverwrites.create(perm.id, {
                allow: BigInt(perm.allow),
                deny: BigInt(perm.deny)
              });
            }
          }
        }
        log(guild, '🔄 **Canaux restaurés** depuis la sauvegarde');
      }
    }
  } catch (error) {
    console.error(`[RESTORE ERROR] ${guild.name}:`, error);
  }
}

// ================================
// SYSTÈME DE LOCKDOWN
// ================================

async function enableLockdown(guild, reason = 'Activité suspecte détectée') {
  try {
    lockdownStatus.set(guild.id, {
      active: true,
      startTime: Date.now(),
      reason: reason,
      originalPermissions: new Map()
    });

    // Sauvegarder les permissions actuelles et retirer les permissions dangereuses
    for (const role of guild.roles.cache.values()) {
      if (role.name !== '@everyone' && !trustedRoles.has(role.id)) {
        const lockdown = lockdownStatus.get(guild.id);
        lockdown.originalPermissions.set(role.id, role.permissions.bitfield.toString());
        
        // Retirer les permissions dangereuses
        const safePermissions = role.permissions.remove([
          PermissionFlagsBits.Administrator,
          PermissionFlagsBits.ManageGuild,
          PermissionFlagsBits.ManageRoles,
          PermissionFlagsBits.ManageChannels,
          PermissionFlagsBits.BanMembers,
          PermissionFlagsBits.KickMembers,
          PermissionFlagsBits.ManageMessages,
          PermissionFlagsBits.ManageWebhooks
        ]);
        
        await role.setPermissions(safePermissions, 'Lockdown de sécurité');
      }
    }

    // Désactiver les invitations
    const invites = await guild.invites.fetch();
    for (const invite of invites.values()) {
      await invite.delete('Lockdown de sécurité');
    }

    log(guild, `🔒 **LOCKDOWN ACTIVÉ** - Raison: ${reason}`);
    
    // Auto-désactivation après timeout
    setTimeout(() => {
      if (lockdownStatus.get(guild.id)?.active) {
        disableLockdown(guild, 'Timeout automatique');
      }
    }, SECURITY_CONFIG.LOCKDOWN_TIMEOUT);

  } catch (error) {
    console.error(`[LOCKDOWN ERROR] ${guild.name}:`, error);
  }
}

async function disableLockdown(guild, reason = 'Manuel') {
  try {
    const lockdown = lockdownStatus.get(guild.id);
    if (!lockdown || !lockdown.active) return;

    // Restaurer les permissions originales
    for (const [roleId, permissions] of lockdown.originalPermissions) {
      const role = guild.roles.cache.get(roleId);
      if (role) {
        await role.setPermissions(BigInt(permissions), 'Fin du lockdown');
      }
    }

    lockdownStatus.delete(guild.id);
    log(guild, `🔓 **LOCKDOWN DÉSACTIVÉ** - Raison: ${reason}`);
  } catch (error) {
    console.error(`[LOCKDOWN DISABLE ERROR] ${guild.name}:`, error);
  }
}

// ================================
// DÉTECTION AMÉLIORÉE DES MENACES
// ================================

function trackAction(guildId, userId, action) {
  const key = `${guildId}-${userId}-${action}`;
  const now = Date.now();
  
  if (!actionCounts.has(key)) actionCounts.set(key, []);
  actionCounts.get(key).push(now);
  
  // Nettoyer les anciennes entrées (1 heure)
  actionCounts.set(key, actionCounts.get(key).filter(t => now - t < 3600000));
  
  return actionCounts.get(key).length;
}

function isPhantomBot(message) {
  // Vérifications avancées pour les bots fantômes
  return (
    message.author.bot && 
    !message.guild.members.cache.has(message.author.id) &&
    !message.webhookId &&
    !whitelist.includes(message.author.id)
  );
}

// ================================
// ÉVÉNEMENTS DE SÉCURITÉ
// ================================

client.once('ready', async () => {
  console.log(`✅ ${client.user.tag} est prêt à sécuriser !`);
  
  // Sauvegarde initiale
  for (const guild of client.guilds.cache.values()) {
    await backupGuildData(guild);
    
    // Initialiser les rôles de confiance
    const adminRoles = guild.roles.cache.filter(r => 
      r.permissions.has(PermissionFlagsBits.Administrator) && 
      r.name.toLowerCase().includes('admin')
    );
    adminRoles.forEach(role => trustedRoles.add(role.id));
  }
  
  // Programmer les sauvegardes automatiques
  setInterval(async () => {
    for (const guild of client.guilds.cache.values()) {
      await backupGuildData(guild);
    }
  }, SECURITY_CONFIG.BACKUP_INTERVAL);

  // Enregistrer les commandes slash
  await registerSlashCommands();
});

client.on('messageCreate', async message => {
  if (!message.guild) return;

  // Vérifier si le serveur est en lockdown
  if (lockdownStatus.get(message.guild.id)?.active && !whitelist.includes(message.author.id)) {
    await message.delete().catch(() => {});
    return;
  }

  if (message.author.bot) {
    // Détection améliorée des bots fantômes
    if (isPhantomBot(message)) {
      log(message.guild, `👻 **BOT FANTÔME DÉTECTÉ** : ${message.author.tag} (ID: ${message.author.id})\nMessage: ${message.content.substring(0, 100)}`);
      await message.delete().catch(() => {});
      return;
    }
    return;
  }

  // Anti-spam amélioré
  const spamKey = `${message.guild.id}-${message.author.id}`;
  const now = Date.now();
  
  if (!messageCounts.has(spamKey)) messageCounts.set(spamKey, []);
  messageCounts.get(spamKey).push(now);
  messageCounts.set(spamKey, messageCounts.get(spamKey).filter(t => now - t < 60000));

  if (messageCounts.get(spamKey).length > SECURITY_CONFIG.MAX_MESSAGES_PER_MINUTE) {
    if (SECURITY_CONFIG.AUTO_BAN_ENABLED && !whitelist.includes(message.author.id)) {
      try {
        await message.guild.members.ban(message.author, { reason: 'Spam automatique détecté' });
        log(message.guild, `🚨 **SPAM DÉTECTÉ** : ${message.author.tag} banni automatiquement`);
      } catch (error) {
        log(message.guild, `⚠️ Impossible de bannir ${message.author.tag} pour spam`);
      }
    }
  }

  // Détection de webhooks suspects
  if (message.webhookId) {
    await handleSuspiciousWebhook(message);
  }
});

// Surveillance des suppressions massives
client.on('channelDelete', async channel => {
  try {
    const audit = await channel.guild.fetchAuditLogs({ type: AuditLogEvent.ChannelDelete, limit: 1 });
    const entry = audit.entries.first();
    
    if (entry && !whitelist.includes(entry.executor.id)) {
      const deleteCount = trackAction(channel.guild.id, entry.executor.id, 'channelDelete');
      
      if (deleteCount >= SECURITY_CONFIG.MAX_CHANNELS_DELETED) {
        await channel.guild.members.ban(entry.executor, { reason: 'Suppression massive de canaux' });
        await enableLockdown(channel.guild, `Suppression massive par ${entry.executor.tag}`);
        log(channel.guild, `🚨 **ATTAQUE DÉTECTÉE** : ${entry.executor.tag} a supprimé ${deleteCount} canaux → Banni et lockdown activé`);
        
        // Restauration automatique
        await restoreGuildData(channel.guild, 'channels');
      } else {
        log(channel.guild, `⚠️ Canal "${channel.name}" supprimé par ${entry.executor.tag} (${deleteCount}/${SECURITY_CONFIG.MAX_CHANNELS_DELETED})`);
      }
    }
  } catch (error) {
    console.error('Erreur channelDelete:', error);
  }
});

client.on('roleDelete', async role => {
  try {
    const audit = await role.guild.fetchAuditLogs({ type: AuditLogEvent.RoleDelete, limit: 1 });
    const entry = audit.entries.first();
    
    if (entry && !whitelist.includes(entry.executor.id)) {
      const deleteCount = trackAction(role.guild.id, entry.executor.id, 'roleDelete');
      
      if (deleteCount >= SECURITY_CONFIG.MAX_ROLES_DELETED) {
        await role.guild.members.ban(entry.executor, { reason: 'Suppression massive de rôles' });
        await enableLockdown(role.guild, `Suppression massive par ${entry.executor.tag}`);
        log(role.guild, `🚨 **ATTAQUE DÉTECTÉE** : ${entry.executor.tag} a supprimé ${deleteCount} rôles → Banni et lockdown activé`);
        
        // Restauration automatique
        await restoreGuildData(role.guild, 'roles');
      } else {
        log(role.guild, `⚠️ Rôle "${role.name}" supprimé par ${entry.executor.tag} (${deleteCount}/${SECURITY_CONFIG.MAX_ROLES_DELETED})`);
      }
    }
  } catch (error) {
    console.error('Erreur roleDelete:', error);
  }
});

client.on('guildBanAdd', async ban => {
  try {
    const audit = await ban.guild.fetchAuditLogs({ type: AuditLogEvent.MemberBanAdd, limit: 1 });
    const entry = audit.entries.first();
    
    if (entry && !whitelist.includes(entry.executor.id)) {
      const banCount = trackAction(ban.guild.id, entry.executor.id, 'memberBan');
      
      if (banCount >= SECURITY_CONFIG.MAX_BANS_PER_HOUR) {
        await ban.guild.members.ban(entry.executor, { reason: 'Bannissements abusifs' });
        await enableLockdown(ban.guild, `Bannissements massifs par ${entry.executor.tag}`);
        log(ban.guild, `🚨 **ATTAQUE DÉTECTÉE** : ${entry.executor.tag} a banni ${banCount} membres → Banni et lockdown activé`);
      } else {
        log(ban.guild, `⚠️ ${ban.user.tag} banni par ${entry.executor.tag} (${banCount}/${SECURITY_CONFIG.MAX_BANS_PER_HOUR})`);
      }
    }
  } catch (error) {
    console.error('Erreur guildBanAdd:', error);
  }
});

client.on('guildMemberAdd', async member => {
  if (member.user.bot && !whitelist.includes(member.id)) {
    await member.ban({ reason: 'Bot non autorisé' });
    log(member.guild, `🚫 **Bot non whitelisté banni** : ${member.user.tag}`);
  }
});

// ================================
// GESTION DES WEBHOOKS SUSPECTS
// ================================

async function handleSuspiciousWebhook(message) {
  try {
    const channel = message.channel;
    const webhooks = await channel.fetchWebhooks();
    const webhook = webhooks.get(message.webhookId);

    if (webhook && !whitelist.includes(webhook.owner?.id)) {
      await webhook.delete('Webhook suspect détecté');
      log(message.guild, `🪝 **Webhook suspect supprimé** : "${webhook.name}" dans #${channel.name}`);
    }
  } catch (error) {
    console.error('Erreur handleSuspiciousWebhook:', error);
  }
}

// ================================
// COMMANDES SLASH
// ================================

async function registerSlashCommands() {
  const commands = [
    new SlashCommandBuilder()
      .setName('lockdown')
      .setDescription('Active/désactive le mode lockdown')
      .addStringOption(option =>
        option.setName('action')
          .setDescription('Action à effectuer')
          .setRequired(true)
          .addChoices(
            { name: 'Activer', value: 'enable' },
            { name: 'Désactiver', value: 'disable' }
          )
      )
      .addStringOption(option =>
        option.setName('raison')
          .setDescription('Raison du lockdown')
          .setRequired(false)
      ),

    new SlashCommandBuilder()
      .setName('restore')
      .setDescription('Restaure les données depuis la sauvegarde')
      .addStringOption(option =>
        option.setName('type')
          .setDescription('Type de données à restaurer')
          .setRequired(true)
          .addChoices(
            { name: 'Tout', value: 'all' },
            { name: 'Rôles', value: 'roles' },
            { name: 'Canaux', value: 'channels' }
          )
      ),

    new SlashCommandBuilder()
      .setName('backup')
      .setDescription('Force une sauvegarde manuelle'),

    new SlashCommandBuilder()
      .setName('whitelist')
      .setDescription('Gère la whitelist de sécurité')
      .addStringOption(option =>
        option.setName('action')
          .setDescription('Action à effectuer')
          .setRequired(true)
          .addChoices(
            { name: 'Ajouter', value: 'add' },
            { name: 'Retirer', value: 'remove' },
            { name: 'Lister', value: 'list' }
          )
      )
      .addUserOption(option =>
        option.setName('utilisateur')
          .setDescription('Utilisateur à ajouter/retirer')
          .setRequired(false)
      ),

    new SlashCommandBuilder()
      .setName('status')
      .setDescription('Affiche le statut de sécurité du serveur')
  ];

  const rest = new REST({ version: '10' }).setToken(process.env.TOKEN);
  
  try {
    await rest.put(Routes.applicationCommands(client.user.id), { body: commands });
    console.log('✅ Commandes slash enregistrées');
  } catch (error) {
    console.error('❌ Erreur enregistrement commandes:', error);
  }
}

client.on('interactionCreate', async interaction => {
  if (!interaction.isChatInputCommand()) return;
  
  // Vérifier les permissions
  if (!interaction.member.permissions.has(PermissionFlagsBits.Administrator) && !whitelist.includes(interaction.user.id)) {
    return interaction.reply({ content: '❌ Vous n\'avez pas les permissions nécessaires.', ephemeral: true });
  }

  const { commandName } = interaction;

  try {
    switch (commandName) {
      case 'lockdown':
        const action = interaction.options.getString('action');
        const reason = interaction.options.getString('raison') || 'Commande manuelle';
        
        if (action === 'enable') {
          await enableLockdown(interaction.guild, reason);
          await interaction.reply('🔒 Lockdown activé !');
        } else {
          await disableLockdown(interaction.guild, 'Commande manuelle');
          await interaction.reply('🔓 Lockdown désactivé !');
        }
        break;

      case 'restore':
        const type = interaction.options.getString('type');
        await restoreGuildData(interaction.guild, type);
        await interaction.reply(`🔄 Restauration ${type} effectuée !`);
        break;

      case 'backup':
        await backupGuildData(interaction.guild);
        await interaction.reply('💾 Sauvegarde manuelle effectuée !');
        break;

      case 'whitelist':
        const wlAction = interaction.options.getString('action');
        const user = interaction.options.getUser('utilisateur');
        
        if (wlAction === 'add' && user) {
          whitelist.push(user.id);
          await interaction.reply(`✅ ${user.tag} ajouté à la whitelist`);
        } else if (wlAction === 'remove' && user) {
          whitelist = whitelist.filter(id => id !== user.id);
          await interaction.reply(`❌ ${user.tag} retiré de la whitelist`);
        } else if (wlAction === 'list') {
          const list = whitelist.map(id => `<@${id}>`).join('\n') || 'Aucun utilisateur';
          await interaction.reply(`📋 **Whitelist:**\n${list}`);
        }
        break;

      case 'status':
        const guild = interaction.guild;
        const lockdown = lockdownStatus.get(guild.id);
        const backupInfo = roleBackup.get(guild.id);
        
        const embed = new EmbedBuilder()
          .setTitle('🛡️ Statut de Sécurité')
          .setColor(lockdown?.active ? 0xff0000 : 0x00ff00)
          .addFields(
            { name: '🔒 Lockdown', value: lockdown?.active ? `Actif (${lockdown.reason})` : 'Inactif', inline: true },
            { name: '💾 Dernière sauvegarde', value: backupInfo ? `${backupInfo.length} rôles sauvés` : 'Aucune', inline: true },
            { name: '👥 Whitelist', value: `${whitelist.length} utilisateurs`, inline: true }
          )
          .setTimestamp();
        
        await interaction.reply({ embeds: [embed] });
        break;
    }
  } catch (error) {
    console.error('Erreur commande:', error);
    await interaction.reply({ content: '❌ Erreur lors de l\'exécution de la commande.', ephemeral: true });
  }
});

// ================================
// FONCTIONS UTILITAIRES
// ================================

function getLogChannel(guild) {
  return guild.channels.cache.find(c => c.name === SECURITY_CONFIG.LOG_CHANNEL_NAME);
}

async function log(guild, content) {
  const logChannel = getLogChannel(guild);
  const timestamp = new Date().toLocaleString('fr-FR');
  const message = `[${timestamp}] ${content}`;
  
  if (logChannel) {
    await logChannel.send({ content: message }).catch(console.error);
  } else {
    console.log(`[LOG][${guild.name}] ${message}`);
  }
}

// Nettoyage périodique des données en mémoire
setInterval(() => {
  const now = Date.now();
  
  // Nettoyer les compteurs de messages (plus de 1 heure)
  for (const [key, timestamps] of messageCounts.entries()) {
    const filtered = timestamps.filter(t => now - t < 3600000);
    if (filtered.length === 0) {
      messageCounts.delete(key);
    } else {
      messageCounts.set(key, filtered);
    }
  }
  
  // Nettoyer les compteurs d'actions
  for (const [key, timestamps] of actionCounts.entries()) {
    const filtered = timestamps.filter(t => now - t < 3600000);
    if (filtered.length === 0) {
      actionCounts.delete(key);
    } else {
      actionCounts.set(key, filtered);
    }
  }
}, 1000 * 60 * 15); // Toutes les 15 minutes

// Gestion des erreurs globales
process.on('unhandledRejection', error => {
  console.error('Erreur non gérée:', error);
});

client.login(process.env.TOKEN);