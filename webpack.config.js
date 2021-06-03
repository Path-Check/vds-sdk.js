const path = require('path');

module.exports = {
  mode: "production",
  entry: "./lib/main.js",
  devtool: "source-map",
  output: {
    filename: 'vds-sdk.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'VDS',
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