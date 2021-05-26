const path = require('path');

module.exports = {
  mode: "production",
  entry: "./lib/index.js",
  devtool: "source-map",
  output: {
    filename: 'icaovds.sdk.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'ICAOVDS',
    libraryTarget: 'umd',
  },
  target: 'web',
  optimization: {
    minimize: true
  },
  node: {
    net: 'empty',
  }
};