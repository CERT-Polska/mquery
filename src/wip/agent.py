from typing import List
from lib.ursadb import UrsaDb
from plugins import PluginManager
import config  # todo remove?
from metadata import Metadata
import logging
from db import AgentTask, JobId, Database, MatchInfo, TaskType
from util import make_sha256_tag


class Agent:
    def __init__(self, group_id: str, ursa_url: str, db: Database) -> None:
        """Creates a new agent instance. Every agents belongs to some group
        (identified by the group_id). There may be multiple agent workers in a
        single group, but they must all work on the same ursadb instance.

        :param group_id: Identifier of the agent group this agent belongs to.
        :type group_id: str
        :param ursa_url: URL to connected ursadb instance. Ideally this should
            be public, because this will allow mquery to collect measurements.
        :type ursa_url: str
        :param db: Reference to main database/task queue.
        :type db: Database
        """
        self.group_id = group_id
        self.ursa_url = ursa_url
        self.db = db
        self.ursa = UrsaDb(self.ursa_url)

        self.plugin_config_version: int = self.db.get_config_version()
        self.plugins = PluginManager(config.PLUGINS, self.db)

        plugins_spec = {
            plugin_class.get_name(): plugin_class.config_fields
            for plugin_class in self.plugins.plugin_classes
        }
        self.db.register_active_agent(
            self.group_id,
            self.ursa_url,
            plugins_spec,
            [
                active_plugin.get_name()
                for active_plugin in self.plugins.active_plugins
            ],
        )

    def get_datasets(self) -> List[str]:
        """Returns a list of dataset IDs, or throws an exception on error."""
        result = self.ursa.topology()

        if "error" in result:
            raise RuntimeError(result["error"])

        return list(result["result"]["datasets"].keys())


    def update_metadata(
        self, job: JobId, orig_name: str, path: str, matches: List[str]
    ) -> None:
        """
        Runs metadata plugins for the given file in a given job.
        :param group_id: Identifier of the agent group this agent belongs to.
        :type group_id: str
        :param ursa_url: URL to connected ursadb instance. Ideally this should
            be public, because this will allow mquery to collect measurements.
        :type ursa_url: str
        :param db: Reference to main database/task queue.
        :type db: Database
        """

        # Initialise default values in the metadata.
        metadata: Metadata = {
            "job": job.hash,
            "path": path,
            "sha256": make_sha256_tag(path),
        }
        # Run all the plugins in configured order.
        for plugin in self.plugins.active_plugins:
            if not plugin.is_extractor:
                continue

            extracted_meta = plugin.run(orig_name, metadata)
            metadata.update(extracted_meta)

        # Remove unnecessary keys from the metadata.
        del metadata["job"]
        del metadata["path"]

        # Update the database.
        match = MatchInfo(orig_name, metadata, matches)
        self.db.add_match(job, match)
