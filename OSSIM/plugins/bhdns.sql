DELETE FROM plugin_sid where plugin_id = "1599";
DELETE FROM plugin WHERE id = "1599";
INSERT INTO plugin (id, type, name, description) VALUES (1599, 1, 'DNS-BH', 'Bind-Malware');
#vous pouvez modifier la priorité et la fiabilité
#ID,SID,cat id, class id, name, priority[0-5], reliability[0-10]
INSERT INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (1599, 1, NULL, NULL, 'Malware_DNS_Requete' ,3 ,3);
